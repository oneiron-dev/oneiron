#!/usr/bin/env python3
'''The port harness (SDK-GENERATOR-RUST, temporary: G6 deletes it with the Python generator).

Each subcommand dumps generate.py's state the way `oneiron-sdk-generator port-harness <subcommand>` dumps the Rust
port's, so a `diff` of the two files proves the port:
  rows --out <file>      generate.py's module-level row sets and constants (the tree is this file's grandparent)
  unicode --out <file>   every character property and case mapping the port's py::text reproduces, and Python's \\b
  floats --out <file>    repr of a fixed corpus of floats
  record --log <file> --out-dir <dir> [--marker-out-dir <dir>]
                         runs outputs() (FORMAT=False) with every Inventory call logged, then dumps each
                         inventory's state; `port-harness replay <log>` replays the log and dumps the same
'''
import argparse
import json
import re
import struct
import sys
import zlib
from pathlib import Path


def rows_dump(out):
    '''generate.py's module level, stopped before the type walk: `facade_types.Inventory` is replaced by a recorder
    before `import generate`, so INVENTORY records the rows it is handed and reads no Rust source.

    ROW_OBJECTS holds every row object once, after the module-level mutations, in first-seen order over MANIFEST,
    ROWS and BOARD_HOST_ROWS (the verb rows, then the synthetic host rows); each set is the list of its rows'
    indexes there, so the dump also shows which sets share an object.'''
    import facade_types
    calls = []

    class InventoryRecorder:
        'Stands in for facade_types.Inventory: records the rows generate.py hands it.'
        def __init__(self, root, rows):
            calls.append(rows)

    facade_types.Inventory = InventoryRecorder
    import generate as g
    objects, index = [], {}

    def ids(rows):
        found = []
        for row in rows:
            if id(row) not in index:
                index[id(row)] = len(objects)
                objects.append(row)
            found.append(index[id(row)])
        return found

    ids(g.MANIFEST['verbs'])
    ids(g.ROWS)
    ids(g.BOARD_HOST_ROWS)
    dump = {
        'ROW_OBJECTS': objects,
        'MANIFEST': {'verbs': ids(g.MANIFEST['verbs'])},
        'HOST_ROWS': ids(g.HOST_ROWS),
        'HOST_RUN_ROWS': ids(g.HOST_RUN_ROWS),
        'HOST_BROWSER_ROWS': ids(g.HOST_BROWSER_ROWS),
        'HOST_BOARD_ROWS': ids(g.HOST_BOARD_ROWS),
        'BROWSER_ROWS': ids(g.BROWSER_ROWS),
        'ROWS': ids(g.ROWS),
        'BOARD_HOST_ROWS': ids(g.BOARD_HOST_ROWS),
        'BOARD_HOST_NAMES': sorted(g.BOARD_HOST_NAMES, key=repr),
        'DEFINITIONS': ids(g.DEFINITIONS),
        'RUN_ROWS': ids(g.RUN_ROWS),
        'SESSION_READS': list(g.SESSION_READS),
        'CODE_MODE_ROWS': ids(g.CODE_MODE_ROWS),
        'SCHEMA_ROWS': ids(g.SCHEMA_ROWS),
        'MCP_NONE_CONTEXTS': list(g.MCP_NONE_CONTEXTS),
        'MCP_SCOPES': sorted(g.MCP_SCOPES),
        'HEADER': g.HEADER,
        'FACADE_ROWS': ids(g.FACADE_ROWS),
        'INVENTORY': [ids(rows) for rows in calls],
        'mcp_rows()': ids(g.mcp_rows()),
        'CORE_VERB_NAMES': g.CORE_VERB_NAMES,
        'CORE_COUNT_DEFAULTS': g.CORE_COUNT_DEFAULTS,
        'CORE_VERB_NAMES_PATH': g.CORE_VERB_NAMES_PATH,
    }
    Path(out).write_text(json.dumps(dump, indent=1) + '\n')


def ranges(name, chars, predicate):
    'One line: the name, then each run of characters the predicate takes, as `FIRST-LAST` hex.'
    line, start, previous = name, None, None
    for c in chars:
        if predicate(c):
            if start is None:
                start = c
        elif start is not None:
            line += f' {ord(start):X}-{ord(previous):X}'
            start = None
        previous = c
    if start is not None:
        line += f' {ord(start):X}-{ord(previous):X}'
    return line + '\n'


def mappings(name, chars, mapping):
    'One line per character the mapping changes: the name, the character, then what it maps to.'
    return ''.join(f'{name} {ord(c):X} {" ".join(f"{ord(m):X}" for m in mapping(c))}\n' for c in chars if mapping(c) != c)


def final_sigma(text):
    return text.lower()[-1] == 'ς'


def unicode_dump(out):
    chars = [chr(cp) for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF]
    dump = ranges('alnum', chars, str.isalnum)
    dump += ranges('word', chars, lambda c: c.isalnum() or c == '_')
    dump += ranges('space', chars, str.isspace)
    dump += ranges('decimal', chars, str.isdecimal)
    dump += ranges('digit', chars, str.isdigit)
    dump += ranges('printable', chars, str.isprintable)
    # Python exposes neither Cased nor Case_Ignorable; these are their definitions in str.islower/isupper/istitle and
    # in the final-sigma rule of str.lower (a case-ignorable character between a cased one and U+03A3 is skipped).
    dump += ranges('cased', chars, lambda c: c.islower() or c.isupper() or c.istitle())
    dump += ranges('case_ignorable', chars, lambda c: final_sigma('A' + c + 'Σ') and not final_sigma('1' + c + 'Σ'))
    dump += ranges('id_start', chars, str.isidentifier)
    dump += ranges('id_continue', chars, lambda c: ('a' + c).isidentifier())
    dump += mappings('upper', chars, str.upper)
    dump += mappings('lower', chars, str.lower)
    dump += mappings('title', chars, str.title)
    dump += ranges('repr_plain', chars, lambda c: repr(c) == f"'{c}'")
    after, before, capitalised = re.compile(r'a\b'), re.compile(r'\ba'), re.compile(r'\b([A-Z]\w*)\b')
    dump += ranges('boundary_after', chars, lambda c: after.search('a' + c) is not None)
    dump += ranges('boundary_before', chars, lambda c: before.search(c + 'a') is not None)
    dump += ranges('capitalised_word', chars, lambda c: capitalised.findall('A' + c) == ['A' + c])
    with open(out, 'w', encoding='utf-8') as f:
        f.write(dump)


def floats_dump(out):
    '''repr of a fixed corpus of floats: every power of two and its two neighbours, decimal sweeps across every
    exponent, and 200,000 floats from a 64-bit linear congruential generator (Knuth's MMIX constants, seed 20261110);
    one line per finite float: its bits in hex and its repr.'''
    lines = []

    def line(bits):
        f = struct.unpack('<d', struct.pack('<Q', bits))[0]
        if f == f and f not in (float('inf'), float('-inf')):
            lines.append(f'{bits:016x} {f!r}\n')

    for k in range(-1074, 1024):
        bits = (k + 1023) << 52 if k >= -1022 else 1 << (k + 1074)
        line(bits - 1)
        line(bits)
        line(bits + 1)
    for exponent in range(-330, 311):
        for mantissa in ('1', '2', '5', '9.999999999999999', '1.2345678901234567', '4.35', '0.1', '3.0000000000000004'):
            line(struct.unpack('<Q', struct.pack('<d', float(f'{mantissa}e{exponent}')))[0])
    state = 20261110
    for _ in range(200000):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        line(state)
    with open(out, 'w', encoding='utf-8') as f:
        f.write(''.join(lines))


# ---------------------------------------------------------------- record (G1b, brief 8.3)

def crc(text):
    'The CRC-32 of a text\'s UTF-8 bytes, as the Rust half computes it.'
    return f'{zlib.crc32(text.encode("utf-8")):08x}'


def row_fields(row):
    'A row as the log carries it: its `input` and `output`, a key absent where the row has none.'
    return {key: row[key] for key in ('input', 'output') if key in row}


def ir_key(key):
    'A declaration key `(crate, file, name, module)` as JSON.'
    return [key[0], key[1], key[2], list(key[3])]


def state_dump(inv):
    'Everything the walk decided, in Python\'s orders (sets sorted).'
    erased = sorted(inv.py_erased())
    return {
        'decls': [[ir_key(key), decl['name'], decl['params'], decl['ir']] for key, decl in inv.decls.items()],
        'order': [ir_key(key) for key in inv.order],
        'names': sorted(name for name in inv.names if isinstance(name, str)),
        'names_not_str': sorted((name for name in inv.names if not isinstance(name, str)),
                                key=lambda name: (type(name).__name__, json.dumps(name))),
        'fallbacks': [list(entry) for entry in inv.fallbacks],
        'opaques': [list(entry) for entry in inv.opaques],
        'variants': [[name, meta] for name, meta in inv.variants.items()],
        'null_fields': [list(entry) for entry in sorted(inv.null_fields, key=lambda e: (e[0], json.dumps(e[1])))],
        'closed': sorted(inv.closed),
        'redacted': sorted(inv.redacted),
        'roots': [[text, ir] for text, ir in inv.roots.items()],
        'preferred': [[ir_key(key), name] for key, name in inv.preferred.items()],
        'root_context': [inv.root_context[0], inv.root_context[1], list(inv.root_context[2])],
        'py_erased': erased,
    }


def index_dump(index):
    'The source index: every file, module, item, impl, macro and import the reader took, in its orders.'
    def item(i):
        return [i.crate, i.file, list(i.module), i.kind, i.top, i.public, i.attrs, list(i.generics),
                crc(i.body), len(i.body), i.shape]
    return {
        'loaded': sorted(index.loaded),
        'files': [[crate, file, crc(text), len(text)] for (crate, file), text in index.files.items()],
        'modules': [[crate, list(module), file] for (crate, module), file in index.modules.items()],
        'items': [[name, [item(i) for i in items]] for name, items in index.items.items()],
        'impls': [[name, [list(entry) for entry in entries]] for name, entries in index.impls.items()],
        'de_impls': [[name, [list(entry) for entry in entries]] for name, entries in index.de_impls.items()],
        'macro_uses': [[name, [list(entry) for entry in entries]] for name, entries in index.macro_uses.items()],
        'macros': [[name, crc(text), len(text)] for name, text in index.macros.items()],
        'use_cache': [[[crate, file], {'names': [[alias, path] for alias, path in names.items()], 'globs': globs}]
                      for (crate, file), (names, globs) in index.use_cache.items()],
        'guesses': sorted(index.guesses),
    }


def dump(out_dir, instances, calls, call):
    'Writes each inventory\'s dump under out_dir/inventory-<n>/ and the call results to out_dir/calls.jsonl.'
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for n, (inv, rows) in enumerate(instances, 1):
        where = out / f'inventory-{n}'
        where.mkdir(exist_ok=True)
        (where / 'state.json').write_text(json.dumps(state_dump(inv), indent=1, sort_keys=True) + '\n')
        (where / 'index.json').write_text(json.dumps(index_dump(inv.index), indent=1, sort_keys=True) + '\n')
        census = call('census', inv, rows)
        (where / 'census.txt').write_text(''.join(line + '\n' for line in census))
        (where / 'typescript.ts').write_text(call('typescript', inv, census))
        (where / 'python.pyi').write_text(call('python', inv, census))
    (out / 'calls.jsonl').write_text(''.join(json.dumps(entry) + '\n' for entry in calls))


def record(log_path, out_dir, marker_dir):
    'Runs outputs() with each top-level Inventory call logged as [method, [inventory, args...]], then dumps.'
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import facade_types
    import uniffi_types
    log = open(log_path, 'w')
    state = {'depth': 0}
    instances, calls = [], []      # [(inventory, rows)], [[method, inventory, result]]

    def ident(inv):
        return next(n for n, (i, _) in enumerate(instances, 1) if i is inv)

    def logged(method, inv, args, run):
        top = state['depth'] == 0
        if top:
            log.write(json.dumps([method, [ident(inv)] + args]) + '\n')
            log.flush()   # a call that raises still leaves its line
        state['depth'] += 1
        try:
            result = run()
        finally:
            state['depth'] -= 1
        if top:
            calls.append([method, ident(inv), result])
        return result

    Inventory = facade_types.Inventory
    orig = {name: getattr(Inventory, name) for name in ('__init__', 'root_ir', 'ts_type', 'py_type', 'census',
                                                         'typescript', 'python')}

    class LoggedNames(set):
        'The inventory\'s `names`: an `update` from outside (catalog_fragment\'s TAKEN) is logged.'
        def update(self, *others):
            others = [list(other) for other in others]   # an iterator is read once, for the log and the update
            added = sorted(set().union(*others))
            return logged('names.update', self.owner, [added], lambda: set.update(self, *others))

    def init(self, root, rows):
        rows = list(rows)   # an iterator is read once, for the log and the inventory
        fields = [row_fields(row) for row in rows]
        instances.append((self, fields))
        logged('Inventory', self, [fields], lambda: orig['__init__'](self, root, rows))
        names = LoggedNames(self.names)
        names.owner = self
        self.names = names

    Inventory.__init__ = init
    Inventory.root_ir = lambda self, text: logged('root_ir', self, [text], lambda: orig['root_ir'](self, text))
    Inventory.ts_type = lambda self, text, prefix='Facade.': logged(
        'ts_type', self, [text, prefix], lambda: orig['ts_type'](self, text, prefix))
    Inventory.py_type = lambda self, text, prefix='Facade.': logged(
        'py_type', self, [text, prefix], lambda: orig['py_type'](self, text, prefix))
    def census(self, rows):
        rows = list(rows)
        return logged('census', self, [[row_fields(row) for row in rows]], lambda: orig['census'](self, rows))
    Inventory.census = census
    Inventory.typescript = lambda self, lines: logged(
        'typescript', self, [lines], lambda: orig['typescript'](self, lines))
    Inventory.python = lambda self, lines: logged('python', self, [lines], lambda: orig['python'](self, lines))
    uniffi_init = uniffi_types.UniffiTypes.__init__

    def uniffi(self, inventory, taken):
        logged('UniffiTypes', inventory, [sorted(taken)], lambda: uniffi_init(self, inventory, taken))
    uniffi_types.UniffiTypes.__init__ = uniffi

    def unlogged(method, inv, *args):
        'A dump\'s own call: run the method without logging it.'
        state['depth'] += 1
        try:
            return orig[method](inv, *args)
        finally:
            state['depth'] -= 1

    import generate
    uniffi_facade = generate.uniffi_facade

    def marked(*args, **kwargs):
        log.write(json.dumps(['marker', 'uniffi_facade']) + '\n')
        if marker_dir:
            dump(marker_dir, instances, calls, unlogged)
        return uniffi_facade(*args, **kwargs)
    generate.uniffi_facade = marked
    generate.FORMAT = False
    generate.outputs()
    log.close()
    dump(out_dir, instances, calls, unlogged)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    rows_parser = sub.add_parser('rows')
    rows_parser.add_argument('--out', required=True)
    unicode_parser = sub.add_parser('unicode')
    unicode_parser.add_argument('--out', required=True)
    record_parser = sub.add_parser('record')
    record_parser.add_argument('--log', required=True)
    record_parser.add_argument('--out-dir', required=True)
    record_parser.add_argument('--marker-out-dir')
    floats_parser = sub.add_parser('floats')
    floats_parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.command == 'rows':
        rows_dump(args.out)
    elif args.command == 'unicode':
        unicode_dump(args.out)
    elif args.command == 'record':
        record(args.log, args.out_dir, args.marker_out_dir)
    elif args.command == 'floats':
        floats_dump(args.out)


if __name__ == '__main__':
    sys.exit(main())
