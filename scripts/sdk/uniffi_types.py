"""UniFFI records and enums for the facade rows' wire types (OF-237).

The facade type inventory (`facade_types.Inventory`) already walks every
facade row's input and output across the engine crates' Rust sources and holds
each reached type's serde wire shape. This module projects that one inventory
into the UniFFI binding: one `#[derive(uniffi::Record)]` or `uniffi::Enum` per
Rust struct or enum the rows reach, written to
`crates/oneiron-uniffi/src/facade_types_generated.rs`. It reads no Rust source
itself.

Each generated type derives serde with exactly the engine type's wire shape:
the same keys, the same enum tagging, the same optional fields, and
`deny_unknown_fields` where the engine type refuses unknown fields (so an
untagged enum picks the variant the engine would). A row converts
at its boundary by a serde round trip through `serde_json::Value`
(`codec::lower_record` / `codec::lift_record`): the record is written as the
row's wire JSON and read as the engine input type, so the engine type's own
serde validates it, and the engine output is written as its wire JSON and read
as the record. Nested types need no conversion of their own.

What UniFFI cannot express stays the crate's `WireJson` leaf, inside the
record and not as the whole argument: a `serde_json::Value`, a recursive type
(a record cannot hold itself), a tuple, a bare unit, an untyped union and a
128-bit integer. A row whose input or output has a shape the inventory could
not read keeps that side on `WireJson` whole.
"""
import json
import re

WIRE = 'crate::WireJson'
# Rust spellings of the integer widths the inventory records; UniFFI carries
# 8 to 64 bits, signed and unsigned, and nothing wider.
WIDTHS = {
    'u8': 'u8', 'u16': 'u16', 'u32': 'u32', 'u64': 'u64', 'usize': 'u64',
    'i8': 'i8', 'i16': 'i16', 'i32': 'i32', 'i64': 'i64', 'isize': 'i64',
    'NonZeroU8': 'u8', 'NonZeroU16': 'u16', 'NonZeroU32': 'u32', 'NonZeroU64': 'u64', 'NonZeroUsize': 'u64',
    'NonZeroI32': 'i32', 'NonZeroI64': 'i64',
}
# Names a generated type may not take: what the generated Rust spells bare, and
# what a foreign binding (Swift, Kotlin, Python) or UniFFI's own scaffolding
# already means by the name. Compared without case, as UniFFI's metadata
# symbols are.
RESERVED = {
    'Option', 'Some', 'None', 'Result', 'Ok', 'Err', 'Vec', 'String', 'Box', 'HashMap', 'Default', 'Clone', 'Debug',
    'PartialEq', 'Serialize', 'Deserialize', 'Self', 'Data', 'Date', 'Url', 'Error', 'Optional', 'Array', 'Dictionary',
    'Set', 'Int', 'Double', 'Float', 'Bool', 'Boolean', 'Character', 'Type', 'Protocol', 'Any', 'Unit', 'Pair', 'Triple',
    'List', 'Map', 'Duration', 'Instant', 'Exception', 'Throwable', 'Nothing', 'Byte', 'Short', 'Long', 'Enum', 'Object',
    'RustBuffer', 'ForeignBytes', 'RustCallStatus', 'Oneiron', 'OneironError', 'WireJson',
    'Copy', 'Send', 'Sync', 'Sized', 'Drop', 'Fn', 'FnMut', 'FnOnce', 'Iterator', 'IntoIterator', 'Extend', 'ToString',
    'ToOwned', 'PartialOrd', 'Eq', 'Ord', 'AsRef', 'AsMut', 'Into', 'From', 'TryFrom', 'TryInto', 'FromIterator', 'Unpin',
    'Hash',
}
RAW_FORBIDDEN = {'crate', 'self', 'super', 'Self'}
KEYWORDS = {
    'as', 'break', 'const', 'continue', 'else', 'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop',
    'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'static', 'struct', 'trait', 'true', 'type', 'unsafe', 'use',
    'where', 'while', 'async', 'await', 'dyn', 'abstract', 'become', 'box', 'do', 'final', 'macro', 'override', 'priv',
    'typeof', 'unsized', 'virtual', 'yield', 'try', 'gen',
}
DERIVES = 'Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize'


def literal(text):
    'A Rust string literal.'
    out = json.dumps(text, ensure_ascii=False)
    if re.search(r'\\[ubf]', out): raise ValueError(f'no Rust literal for {text!r}')
    return out


def snake(key):
    'A field identifier for a wire key.'
    name = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', key).lower()
    name = re.sub(r'[^a-z0-9_]+', '_', name).strip('_') or 'value'
    if name[0].isdigit(): name = 'field_' + name
    if name in RAW_FORBIDDEN: return name + '_'
    return 'r#' + name if name in KEYWORDS else name


class UniffiTypes:
    'The UniFFI mirrors of the inventory types the facade rows reach.'

    def __init__(self, inventory, taken):
        self.inv = inventory
        self.taken = {name.upper() for name in set(taken) | RESERVED}
        self.mirrors = {}    # (declaration key, closed arguments) -> name
        self.items = []      # rendered items, in first-reached order
        self.leaves = {}     # where -> why it stays a WireJson leaf
        self.recursive = self.cycles()

    # ---- the reference graph

    def cycles(self):
        'Declarations on a reference cycle: a UniFFI record cannot hold itself.'
        edges = {key: set() for key in self.inv.decls}
        for key, decl in self.inv.decls.items():
            stack = [decl['ir']]
            while stack:
                node = stack.pop()
                kind = node[0]
                if kind == 'ref': edges[key].add(node[1]); stack.extend(node[2])
                elif kind in ('array', 'option', 'map', 'partial'): stack.append(node[1])
                elif kind in ('tuple', 'union', 'and'): stack.extend(node[1])
                elif kind == 'object': stack.extend(field[1] for field in node[1])
        index, low, stack, on, found, counter = {}, {}, [], set(), set(), [0]

        def visit(start):
            # Tarjan's strongly connected components, iteratively.
            work = [(start, iter(sorted(edges[start], key=repr)))]
            index[start] = low[start] = counter[0]; counter[0] += 1; stack.append(start); on.add(start)
            while work:
                node, children = work[-1]
                child = next(children, None)
                if child is not None:
                    if child not in index:
                        index[child] = low[child] = counter[0]; counter[0] += 1; stack.append(child); on.add(child)
                        work.append((child, iter(sorted(edges[child], key=repr))))
                    elif child in on:
                        low[node] = min(low[node], index[child])
                    continue
                work.pop()
                if work: low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop(); on.discard(member); component.append(member)
                        if member == node: break
                    if len(component) > 1 or node in edges[node]: found.update(component)

        for key in sorted(edges, key=repr):
            if key not in index: visit(key)
        return found

    # ---- roots

    def root(self, text):
        'The UniFFI type a row type crosses as, or None when it stays WireJson whole.'
        ir = self.inv.root_ir(text)
        unknown, _ = self.inv.reach(ir, set())
        if unknown: return None
        mirror = self.rt(ir, {}, text)
        return None if mirror == WIRE else mirror

    @staticmethod
    def empty(mirror_ir):
        return mirror_ir[0] == 'object' and not mirror_ir[1]

    def root_is_empty(self, text):
        'Whether a row type is a record with no fields, so the method takes no argument.'
        ir = self.inv.root_ir(text)
        if ir[0] == 'ref': ir = self.inv.decls[ir[1]]['ir']
        return self.empty(ir)

    # ---- types

    def leaf(self, where, why):
        self.leaves.setdefault(where, why)
        return WIRE

    def close(self, node, subst):
        'An IR value with the generic parameters in scope substituted.'
        kind = node[0]
        if kind == 'param': return subst.get(node[1], ('unknown', 'unbound parameter'))
        if kind in ('array', 'option', 'map', 'partial'): return (kind, self.close(node[1], subst))
        if kind in ('tuple', 'union', 'and'): return (kind, [self.close(m, subst) for m in node[1]])
        if kind == 'object': return (kind, [(k, self.close(v, subst), o) for k, v, o in node[1]], node[2])
        if kind == 'ref': return ('ref', node[1], [self.close(a, subst) for a in node[2]])
        return node

    def mangle(self, node):
        'A type argument as part of a monomorphised name.'
        kind = node[0]
        if kind == 'ref':
            return self.inv.decls[node[1]]['name'] + ''.join(self.mangle(a) for a in node[2])
        if kind == 'array': return self.mangle(node[1]) + 'List'
        if kind == 'option': return 'Optional' + self.mangle(node[1])
        if kind == 'map': return self.mangle(node[1]) + 'Map'
        if kind == 'prim':
            if node[1] == 'int': return WIDTHS.get(node[2] if len(node) > 2 else 'i64', 'Int').title()
            return {'string': 'String', 'float': 'Float', 'bool': 'Bool', 'null': 'Unit'}[node[1]]
        if kind == 'opaque': return 'Json'
        return 'Value'

    def rt(self, node, subst, where):
        'The Rust spelling of an IR value in the generated module.'
        kind = node[0]
        if kind == 'prim':
            if node[1] == 'int':
                width = WIDTHS.get(node[2] if len(node) > 2 else 'i64')
                return width or self.leaf(where, 'a 128-bit integer')
            if node[1] == 'null': return self.leaf(where, 'a unit value')
            return {'string': 'String', 'float': 'f64', 'bool': 'bool'}[node[1]]
        if kind == 'opaque': return WIRE
        if kind == 'param': return self.rt(subst.get(node[1], ('unknown', 'unbound')), {}, where)
        if kind == 'array': return f'Vec<{self.rt(node[1], subst, where)}>'
        if kind == 'option':
            inner = self.rt(node[1], subst, where)
            return inner if inner.startswith('Option<') else f'Option<{inner}>'
        if kind == 'map': return f'std::collections::HashMap<String, {self.rt(node[1], subst, where)}>'
        if kind == 'ref': return self.ref(node, subst, where)
        if kind == 'tuple': return self.leaf(where, 'a tuple')
        if kind == 'union': return self.leaf(where, 'an untyped union')
        if kind == 'unknown': return self.leaf(where, 'a shape the inventory could not read')
        if kind == 'never': return self.leaf(where, 'an enum with no variants')
        return self.leaf(where, f'an inline {kind}')

    def ref(self, node, subst, where):
        key = node[1]
        decl = self.inv.decls[key]
        args = [self.close(a, subst) for a in node[2]]
        if key in self.recursive: return self.leaf(where, f'the recursive type {decl["name"]}')
        inner = dict(zip(decl['params'], args))
        ir, meta = decl['ir'], self.inv.variants.get(decl['name'])
        if meta is None and ir[0] not in ('object', 'and'):
            # A newtype, alias or handwritten codec: its wire value, inline.
            return self.rt(ir, inner, decl['name'])
        if meta is not None and not meta['variants']: return self.leaf(decl['name'], 'an enum with no variants')
        mkey = (key, repr(args))
        if mkey in self.mirrors: return self.mirrors[mkey]
        name = self.allocate(decl['name'] + ''.join(self.mangle(a) for a in args))
        self.mirrors[mkey] = name
        item = decl['item']
        doc = '/// `' + '::'.join((item.crate,) + item.module + (item.name,)) + '`'
        if args: doc += ' with ' + ', '.join(f'`{p}` = `{self.mangle(a)}`' for p, a in zip(decl['params'], args))
        doc += '.\n'
        if meta is not None:
            self.items.append(doc + self.enum(name, decl['name'], meta, inner))
        else:
            self.items.append(doc + self.record(name, decl['name'], ir, inner))
        return name

    def allocate(self, base):
        name, n = base, 2
        if name.upper() in self.taken: name = 'Wire' + base
        while name.upper() in self.taken:
            name = f'Wire{base}{n}'; n += 1
        self.taken.add(name.upper())
        return name

    # ---- items

    def fields(self, owner, body, subst, public):
        'The fields of a record or a struct variant, and its struct tag, if any.'
        flats, record = (body[1][:-1], body[1][-1]) if body[0] == 'and' else ([], body)
        out, used, tag = [], set(), None

        def ident(text):
            name, n = snake(text), 2
            while name in used:
                name = f'{snake(text)}_{n}'; n += 1
            used.add(name)
            return name

        prefix = 'pub ' if public else ''
        for key, value, optional in record[1]:
            where = f'{owner}.{key}'
            if value[0] == 'lit':
                if tag is not None: raise ValueError(f'{owner}: two tag fields')
                tag = (key, value[1]); continue
            typ = self.rt(value, subst, where)
            attrs = [f'rename = {literal(key)}']
            if typ.startswith('Option<'):
                attrs.append('default')
                if (owner, key) not in self.inv.null_fields: attrs.append('skip_serializing_if = "Option::is_none"')
            elif optional:
                typ = f'Option<{typ}>'
                attrs += ['default', 'skip_serializing_if = "Option::is_none"']
            out.append(f'#[serde({", ".join(attrs)})]\n{prefix}{ident(key)}: {typ},\n')
        for flat in flats:
            partial = flat[0] == 'partial'
            value = flat[1] if partial else flat
            typ = self.rt(value, subst, owner + '.(flattened)')
            if partial and not typ.startswith('Option<'): typ = f'Option<{typ}>'
            label = self.inv.decls[value[1]]['name'] if value[0] == 'ref' else 'flattened'
            out.append(f'#[serde(flatten)]\n{prefix}{ident(label)}: {typ},\n')
        return out, tag

    def record(self, name, owner, ir, subst):
        fields, tag = self.fields(owner, ir, subst, True)
        head = f'#[derive({DERIVES}, uniffi::Record)]\n'
        if tag: head += f'#[serde(tag = {literal(tag[0])}, rename = {literal(tag[1])})]\n'
        if owner in self.inv.closed: head += '#[serde(deny_unknown_fields)]\n'
        return head + f'pub struct {name} {{\n' + ''.join(fields) + '}\n'

    def enum(self, name, owner, meta, subst):
        tag, content, untagged = meta['tag'], meta['content'], meta['untagged']
        head = f'#[derive({DERIVES}, uniffi::Enum)]\n'
        if untagged: head += '#[serde(untagged)]\n'
        elif tag and content: head += f'#[serde(tag = {literal(tag)}, content = {literal(content)})]\n'
        elif tag: head += f'#[serde(tag = {literal(tag)})]\n'
        if owner in self.inv.closed: head += '#[serde(deny_unknown_fields)]\n'
        body = ''
        for variant in meta['variants']:
            vname, shape, member = variant['name'], variant['shape'], variant['member']
            where = f'{owner}.{vname}'
            payload = self.payload(meta, variant)
            attrs = [] if untagged else [f'rename = {literal(variant["label"])}']
            if variant['untagged'] and not untagged: attrs.append('untagged')
            if variant['other']: attrs.append('other')
            body += f'#[serde({", ".join(attrs)})]\n' if attrs else ''
            if shape == 'unit':
                body += f'{vname},\n'
            elif shape == 'newtype':
                body += f'{vname}({self.rt(payload, subst, where)}),\n'
            elif shape == 'tuple':
                body += f'{vname}(' + ', '.join(self.rt(v, subst, where) for v in payload[1]) + '),\n'
            else:
                if tag and not content and not untagged and not variant['untagged']:
                    payload = strip_marker(payload, tag)
                fields, _ = self.fields(where, payload, subst, False)
                body += f'{vname} {{\n' + ''.join(fields) + '},\n'
        return head + f'pub enum {name} {{\n' + body + '}\n'

    @staticmethod
    def payload(meta, variant):
        'A variant\'s payload IR (its value, or its struct body), out of the member the inventory built.'
        member, shape = variant['member'], variant['shape']
        if shape == 'unit': return None
        if meta['untagged'] or variant['untagged']: return member
        tag, content = meta['tag'], meta['content']
        if tag and content:
            return next(value for key, value, _ in member[1] if key == content)
        if tag:
            return member[1][0] if shape in ('newtype', 'tuple') else member
        return member[1][0][1]

    # ---- output

    def render(self, header, census):
        out = header
        out += '// UniFFI records and enums for the Rust types the facade rows reach, from the\n'
        out += '// facade type inventory (scripts/sdk/facade_types.py). Each derives serde with\n'
        out += '// the engine type\'s own wire shape; a row converts at its boundary through\n'
        out += '// that shape (crate::codec::lower_record / lift_record).\n'
        out += ''.join(f'// {line}\n' for line in census)
        out += ('#![allow(\n    clippy::large_enum_variant,\n    clippy::enum_variant_names,\n    clippy::upper_case_acronyms,\n'
                '    reason = "each type mirrors one engine type, its names and its variants"\n)]\n\n')
        return out + '\n'.join(self.items)


def strip_marker(body, tag):
    'An internally tagged struct variant\'s body without its tag field.'
    def strip(record):
        return ('object', [f for f in record[1] if not (f[0] == tag and f[1][0] == 'lit')], record[2])
    if body[0] == 'and': return ('and', body[1][:-1] + [strip(body[1][-1])])
    return strip(body)
