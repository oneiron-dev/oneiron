#!/usr/bin/env python3
"""Generate guest SDK, prompt declarations and import names from code-run.wit.

Rust types come from wasmtime::component::bindgen!, not this generator.
@json / @json-list annotate JSON carried through WIT strings. @js pins names.
Unrecognized types and unannotated imports fail closed.
"""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
WIT = ROOT / "crates/oneiron/wit/code-run.wit"
OUT = WIT.parent / "generated"


def camel(name):
    first, *rest = name.split("-")
    return first + "".join(part.title() for part in rest)


def pascal(name):
    return "".join(part.title() for part in name.split("-"))


def split_types(text):
    depth, start, out = 0, 0, []
    for i, ch in enumerate(text):
        depth += (ch == "<") - (ch == ">")
        if ch == "," and depth == 0:
            out.append(text[start:i].strip())
            start = i + 1
    if text[start:].strip():
        out.append(text[start:].strip())
    return out


def schema(source):
    records = {}
    for name, body in re.findall(r"record\s+([\w-]+)\s*\{([^}]+)\}", source):
        fields = []
        for field in split_types(body):
            mode = "json-list" if "// @json-list" in field else "json" if "// @json" in field else None
            field = re.sub(r"//[^\n]*", "", field).strip()
            if not field:
                continue
            key, typ = field.split(":", 1)
            fields.append({"name": camel(key.strip()), "type": typ.strip(), "json": mode})
        records[name] = fields
    variants = {}
    for name, body in re.findall(r"variant\s+([\w-]+)\s*\{([^}]+)\}", source):
        variants[name] = []
        for case in split_types(body):
            match = re.fullmatch(r"([\w-]+)\(([\w-]+)\)", case)
            if not match:
                raise ValueError(f"unrecognized WIT variant case: {case}")
            variants[name].append(match.groups())
    imports = []
    for js, name, args, result in re.findall(r"// @js ([\w.]+)\s+import ([\w-]+): func\(([^)]*)\) -> ([^;]+);", source):
        params = []
        for arg in split_types(args):
            key, typ = arg.split(":", 1)
            params.append({"name": camel(key.strip()), "type": typ.strip()})
        if result.startswith("result<"):
            ok, error = split_types(result[7:-1])
            if error != "string":
                raise ValueError("SDK error type must be string")
            result = ok
        imports.append({"js": js, "wit": name, "params": params, "result": result,
                        "async": not js.startswith("oneiron.")})
    if len(imports) != len(re.findall(r"\bimport\s+[\w-]+:", source)):
        raise ValueError("every WIT import must have @js")
    if len({row['js'] for row in imports}) != len(imports):
        raise ValueError("duplicate JS import name")
    return records, variants, imports


def generate(source):
    records, variants, imports = schema(source)

    def ts(typ):
        if typ.startswith("option<"):
            return ts(typ[7:-1]) + " | undefined"
        if typ == "list<u8>":
            return "Uint8Array"
        if typ.startswith("list<"):
            return "Array<" + ts(typ[5:-1]) + ">"
        if typ in ["u8", "u32", "u64", "f32"]:
            return "number"
        if typ in ["string", "bool"]:
            return {"string": "string", "bool": "boolean"}[typ]
        if typ in records or typ in variants:
            return "OneironCodeRun." + pascal(typ)
        raise ValueError(f"unknown WIT type: {typ}")

    dts = ["// Generated from code-run.wit; do not edit.", "declare namespace OneironCodeRun {"]
    for name, fields in records.items():
        items = []
        for field in fields:
            typ = "unknown[]" if field['json'] == 'json-list' else "unknown" if field['json'] else ts(field['type'])
            optional = "?" if field['type'].startswith('option<') else ""
            items.append(f"{field['name']}{optional}: {typ};")
        dts.append(f"  interface {pascal(name)} {{ {' '.join(items)} }}")
    for name, cases in variants.items():
        dts.append("  type " + pascal(name) + " = " + " | ".join(
            "{ tag: " + json.dumps(tag) + "; val: " + ts(typ) + " }" for tag, typ in cases) + ";")
    dts.append("}")
    tree = {}
    for row in imports:
        node = tree
        *namespaces, function = row['js'].split('.')
        for namespace in namespaces:
            node = node.setdefault(namespace, {})
        node[function] = row

    def emit(node, indent=0):
        for name, value in node.items():
            prefix = "  " * indent
            if 'wit' not in value:
                dts.append(prefix + ("declare " if indent == 0 else "") + f"namespace {name} {{")
                emit(value, indent + 1)
                dts.append(prefix + "}")
            else:
                args = ", ".join(f"{arg['name']}: {ts(arg['type'])}" for arg in value['params'])
                result = ts(value['result'])
                if value['async']:
                    result = f"Promise<{result}>"
                dts.append(prefix + f"function {name}({args}): {result};")
    emit(tree)
    metadata = json.dumps({"records": records, "imports": imports}, separators=(',', ':'))
    js = '// Generated from code-run.wit; do not edit.\nconst schema = ' + metadata + ';\n' + SDK_RUNTIME
    rust = '// Generated from code-run.wit; do not edit.\n&[\n' + ''.join(
        f'    ({json.dumps(row["wit"])}, {json.dumps(row["js"])}),\n' for row in imports) + ']\n'
    return {"code-run.d.ts": '\n'.join(dts) + '\n', "code-run.mjs": js, "imports.rs": rust}


SDK_RUNTIME = '\nfunction convert(type, value, encode) {\n  if (type.startsWith("option<")) return value == null ? undefined : convert(type.slice(7, -1), value, encode);\n  if (type === "list<u8>") return value instanceof Uint8Array ? value : new Uint8Array(value);\n  if (type.startsWith("list<")) return value.map(item => convert(type.slice(5, -1), item, encode));\n  if (["u64", "u32", "u8"].includes(type)) {\n    const n = Number(value);\n    const max = type === "u8" ? 255 : type === "u32" ? 4294967295 : Number.MAX_SAFE_INTEGER;\n    if (!Number.isSafeInteger(n) || n < 0 || n > max) throw new RangeError("invalid guest integer");\n    return n;\n  }\n  if (schema.records[type]) {\n    const result = {};\n    for (const field of schema.records[type]) {\n      const v = value[field.name];\n      if (field.json) {\n        const transform = encode ? JSON.stringify : JSON.parse;\n        result[field.name] = field.json === "json-list" ? v.map(item => transform(item)) : transform(v);\n        if (result[field.name] === undefined) throw new TypeError("missing guest JSON field");\n      } else result[field.name] = convert(field.type, v, encode);\n    }\n    return result;\n  }\n  return value;\n}\n\n// The guest bootstrap injects the ABI. Missing imports stay absent: foreign\n// SDK instances cannot grow write methods that their component did not import.\nexport function createHostSdk(abi) {\n  const sdk = Object.create(null);\n  for (const row of schema.imports) {\n    if (!Object.hasOwn(abi, row.wit)) continue;\n    let target = sdk;\n    const parts = row.js.split(".");\n    for (const part of parts.slice(0, -1)) target = target[part] ??= Object.create(null);\n    target[parts.at(-1)] = (...args) => {\n      const values = row.params.map((param, i) => convert(param.type, args[i], true));\n      const result = abi[row.wit](...values);\n      return row.async ? Promise.resolve(result).then(v => convert(row.result, v, false)) : convert(row.result, result, false);\n    };\n  }\n  return sdk;\n}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for name, content in generate(WIT.read_text()).items():
        path = OUT / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if stale:
        print("SANDBOX-WIT-STALE: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
