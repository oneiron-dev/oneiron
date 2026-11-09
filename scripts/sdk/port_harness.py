#!/usr/bin/env python3
'''The port harness (SDK-GENERATOR-RUST, temporary: G6 deletes it with the Python generator).

Each subcommand dumps generate.py's state the way `oneiron-sdk-generator port-harness <subcommand>` dumps the Rust
port's, so a `diff` of the two files proves the port:
  rows --out <file>      generate.py's module-level row sets and constants (the tree is this file's grandparent)
  unicode --out <file>   every character property and case mapping the port's py::text reproduces, and Python's \\b
  floats --out <file>    repr of a fixed corpus of floats
'''
import argparse
import json
import re
import struct
import sys
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    rows_parser = sub.add_parser('rows')
    rows_parser.add_argument('--out', required=True)
    unicode_parser = sub.add_parser('unicode')
    unicode_parser.add_argument('--out', required=True)
    floats_parser = sub.add_parser('floats')
    floats_parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.command == 'rows':
        rows_dump(args.out)
    elif args.command == 'unicode':
        unicode_dump(args.out)
    elif args.command == 'floats':
        floats_dump(args.out)


if __name__ == '__main__':
    sys.exit(main())
