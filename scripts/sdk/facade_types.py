"""Generate wire DTO declarations from the Rust facade's plain serde records."""
import re
from pathlib import Path

SOURCES = [
    'crates/oneiron/src/task_verb/sdk.rs',
    'crates/oneiron/src/task_verb/sdk_memory.rs',
    'crates/oneiron/src/memory/claims/mod.rs',
    'crates/oneiron/src/memory/structural/types.rs',
    'crates/oneiron/src/memory/reads.rs',
    'crates/oneiron/src/memory/export.rs',
    'crates/oneiron/src/memory/witness/types.rs',
]


def declarations(root: Path):
    records = {}
    enums = {}
    for path in SOURCES:
        text = (root / path).read_text()
        text = re.sub(r'(pub struct \w+)\s*\{\s*}', r'\1 {\n}', text)
        for match in re.finditer(r'pub struct (\w+)(?:<[^>]+>)?\s*\{(.*?)^}', text, re.M | re.S):
            name, body = match.groups()
            fields = []
            for field in re.finditer(r'((?:[ \t]*#\[[^\n]*\]\n)*)[ \t]*pub (\w+): ([^\n]+),', body):
                attrs, key, typ = field.groups()
                rename = re.search(r'rename = "([^\"]+)"', attrs)
                # A field serialized through a base64 codec is a string on the wire.
                if re.search(r'with = "[^"]*base64', attrs):
                    typ = 'String'
                fields.append((rename.group(1) if rename else key, typ, 'default' in attrs))
            records[name] = fields
        for match in re.finditer(r'pub enum (\w+)\s*\{(.*?)^}', text, re.M | re.S):
            name, body = match.groups()
            variants = []
            for variant in re.finditer(r'^    (\w+)(?:\((\w+)\))?,', body, re.M):
                key, inner = variant.groups()
                variants.append(inner or '"' + re.sub(r'(?<!^)(?=[A-Z])', '_', key).lower() + '"')
            if variants:
                enums[name] = variants
    return records, enums


def wire_type(value, known, prefix=''):
    value = value.strip()
    for container in ('Option', 'Vec'):
        if value.startswith(container + '<') and value.endswith('>'):
            inner = wire_type(value[len(container) + 1:-1], known, prefix)
            return inner + ' | null' if container == 'Option' else '(' + inner + ')[]'
    if 'ScopedReadResult<' in value:
        inner = value[value.index('<') + 1:-1]
        return '{value: ' + wire_type(inner, known, prefix) + '; narrowing: unknown}'
    if value.endswith('serde_json::Value') or value == 'serde_json::Value':
        return 'unknown'
    leaf = value.rsplit('::', 1)[-1]
    if leaf in ('String', 'str'): return 'string'
    if leaf == 'bool': return 'boolean'
    if re.fullmatch(r'(?:[uif]\d+|usize|isize)', leaf): return 'number'
    if leaf in known: return prefix + leaf
    return 'unknown'


def typescript(root):
    records, enums = declarations(root)
    known = set(records) | set(enums)
    out = '// Generated from Rust facade DTOs by scripts/sdk/generate.py.\n'
    for name, fields in records.items():
        out += 'export type ' + name + ' = {\n'
        for key, typ, defaulted in fields:
            optional = '?' if typ.startswith('Option<') or defaulted else ''
            out += '  ' + key + optional + ': ' + wire_type(typ, known) + '\n'
        out += '}\n'
    for name, variants in enums.items():
        out += 'export type ' + name + ' = ' + ' | '.join(variants) + '\n'
    return out, known
