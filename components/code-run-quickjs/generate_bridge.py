#!/usr/bin/env python3
"""Generate the QuickJS-to-C adapters from the canonical WIT SDK inventory."""
import json
import re
import sys
from pathlib import Path

sdk = Path(sys.argv[1]).read_text()
schema = json.loads(re.search(r"const schema = (.*);", sdk).group(1))
records = schema["records"]

def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().replace("-", "_")

def token(ty):
    return ty.replace("<", "_").replace(">", "").replace("-", "_")

def ctype(ty):
    return {"u8": "uint8_t", "u32": "uint32_t", "u64": "uint64_t",
            "f32": "float", "bool": "bool"}.get(ty, "guest_" + token(ty) + "_t")

def owns_memory(ty):
    if ty == "string" or ty.startswith("list<"):
        return True
    if ty.startswith("option<"):
        return owns_memory(ty[7:-1])
    return any(owns_memory(field["type"]) for field in records.get(ty, []))

def release(ty, value):
    if not owns_memory(ty):
        return ""
    return "guest_" + token(ty) + "_free(&" + value + ");"

parts = ['/* Generated from the canonical WIT inventory. */']
seen = set()

def emit(ty):
    if ty in seen or ty == "proposal-delta":
        return
    seen.add(ty)
    ct = ctype(ty)
    decode = []
    encode = []
    if ty.startswith("option<"):
        inner = ty[7:-1]
        emit(inner)
        decode = ['if (JS_IsUndefined(v) || JS_IsNull(v)) return true;',
                  'out->is_some = true;', f'return from_{token(inner)}(ctx, v, &out->val);']
        encode = [f'return v->is_some ? to_{token(inner)}(ctx, &v->val) : JS_UNDEFINED;']
    elif ty.startswith("list<"):
        inner = ty[5:-1]
        emit(inner)
        decode = ['JSValue size = JS_GetPropertyStr(ctx, v, "length");',
                  'uint32_t length;',
                  'if (JS_ToUint32(ctx, &length, size) < 0) { JS_FreeValue(ctx, size); return false; }',
                  'JS_FreeValue(ctx, size);',
                  f'if (length > {"MESSAGE_LIMIT" if inner == "u8" else "10000"}) return bad_value(ctx);',
                  'out->ptr = calloc(length, sizeof(*out->ptr));',
                  'if (length && !out->ptr) return bad_value(ctx);',
                  'out->len = length;',
                  'for (uint32_t i = 0; i < length; ++i) {',
                  ' JSValue item = JS_GetPropertyUint32(ctx, v, i);',
                  f' bool ok = from_{token(inner)}(ctx, item, &out->ptr[i]);',
                  ' JS_FreeValue(ctx, item); if (!ok) return false;',
                  '}', 'return true;']
        encode = ['JSValue out = JS_NewArray(ctx);',
                  'for (size_t i = 0; i < v->len; ++i)',
                  f' JS_SetPropertyUint32(ctx, out, i, to_{token(inner)}(ctx, &v->ptr[i]));',
                  'return out;']
    elif ty in records:
        for field in records[ty]:
            emit(field['type'])
        for i, field in enumerate(records[ty]):
            fty, name = token(field['type']), snake(field['name'])
            decode.extend(['{', f'JSValue item = JS_GetPropertyStr(ctx, v, "{field["name"]}");',
                           f'bool ok = from_{fty}(ctx, item, &out->{name});',
                           'JS_FreeValue(ctx, item); if (!ok) return false;', '}'])
            encode.append(f'JS_SetPropertyStr(ctx, out, "{field["name"]}", to_{fty}(ctx, &v->{name}));')
        decode.append('return true;')
        encode = ['JSValue out = JS_NewObject(ctx);'] + encode + ['return out;']
    elif ty == 'string':
        decode = ['if (!JS_IsString(v)) return bad_value(ctx);',
                  'size_t length; const char *text = JS_ToCStringLen(ctx, &length, v);',
                  'if (!text) return false;',
                  'if (length > MESSAGE_LIMIT) { JS_FreeCString(ctx, text); return bad_value(ctx); }',
                  'out->ptr = malloc(length + 1);',
                  'if (!out->ptr) { JS_FreeCString(ctx, text); return bad_value(ctx); }',
                  'memcpy(out->ptr, text, length); out->len = length;',
                  'JS_FreeCString(ctx, text); return true;']
        encode = ['return JS_NewStringLen(ctx, (const char *)v->ptr, v->len);']
    elif ty == 'bool':
        decode = ['if (!JS_IsBool(v)) return bad_value(ctx);', '*out = JS_ToBool(ctx, v); return true;']
        encode = ['return JS_NewBool(ctx, *v);']
    else:
        maxval = {'u8':'255', 'u32':'4294967295.0', 'u64':'9007199254740991.0', 'f32':'FLT_MAX'}[ty]
        decode = ['double n; if (!JS_IsNumber(v) || JS_ToFloat64(ctx, &n, v) < 0) return bad_value(ctx);',
                  f'if (!isfinite(n) || n > {maxval}' + (f' || n < -{maxval}' if ty=='f32' else ' || n < 0 || floor(n) != n') + ') return bad_value(ctx);',
                  f'*out = ({ct})n; return true;']
        encode = ['return JS_NewFloat64(ctx, *v);']
    parts.append(f'static bool from_{token(ty)}(JSContext *ctx, JSValueConst v, {ct} *out) {{\n' + '\n'.join(decode) + '\n}')
    parts.append(f'static JSValue to_{token(ty)}(JSContext *ctx, const {ct} *v) {{\n' + '\n'.join(encode) + '\n}')

for row in schema['imports']:
    for p in row['params']: emit(p['type'])
    emit(row['result'])
emit('file-proposal')
# Claim input is generated in both tiers: the foreign output uses it for proposals.
emit('claim-input')

for row in schema['imports']:
    first_party = row['js'].startswith('self.') or row['js'] == 'ask'
    if first_party: parts.append('#ifndef ONEIRON_FOREIGN')
    name, result = snake(row['wit']), row['result']
    lines = [f'static JSValue call_{name}(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {{',
             '(void)this_val;', f'if (argc != {len(row["params"])}) return JS_ThrowTypeError(ctx, "wrong host argument count");']
    params = []
    clean = []
    for i, p in enumerate(row['params']):
        ty = p['type']
        lines.extend([f'{ctype(ty)} arg{i} = {{0}};'])
        params.append(f'&arg{i}' if ty not in ['u8','u32','u64','f32','bool'] else f'arg{i}')
        clean.append(release(ty, f'arg{i}'))
    for i, p in enumerate(row['params']):
        lines.append(f'if (!from_{token(p["type"])}(ctx, argv[{i}], &arg{i})) {{ ' + ' '.join(clean) + ' return JS_EXCEPTION; }')
    if row['wit'] == 'clock-now-unix-ms':
        lines.extend(['uint64_t result = guest_clock_now_unix_ms();', 'return JS_NewFloat64(ctx, (double)result);'])
    else:
        args = ', '.join(params + ['&result', '&error'])
        lines.extend([f'{ctype(result)} result = {{0}};', 'guest_string_t error = {0};',
                      f'bool ok = guest_{name}({args});'] + clean +
                     ['if (!ok) { JSValue thrown = JS_NewStringLen(ctx, (char *)error.ptr, error.len); guest_string_free(&error); return JS_Throw(ctx, thrown); }',
                      f'JSValue value = to_{token(result)}(ctx, &result);', release(result, 'result'), 'return value;'])
    parts.append('\n'.join(lines + ['}']))
    if first_party: parts.append('#endif')
parts.append('static JSValue make_abi(JSContext *ctx) {\n JSValue abi = JS_NewObject(ctx);')
for row in schema['imports']:
    if row['js'].startswith('self.') or row['js'] == 'ask': parts.append('#ifndef ONEIRON_FOREIGN')
    name = snake(row['wit'])
    parts.append(f'JS_SetPropertyStr(ctx, abi, "{row["wit"]}", JS_NewCFunction(ctx, call_{name}, "{row["wit"]}", {len(row["params"])}));')
    if row['js'].startswith('self.') or row['js'] == 'ask': parts.append('#endif')
parts.append('return abi;\n}')
Path(sys.argv[2]).write_text('\n\n'.join(parts) + '\n')
