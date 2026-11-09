#!/usr/bin/env python3
'''The port harness (SDK-GENERATOR-RUST, temporary: G6 deletes it with the Python generator).

Each subcommand dumps generate.py's state the way `oneiron-sdk-generator port-harness <subcommand>` dumps the Rust
port's, so a `diff` of the two files proves the port:
  unicode --out <file>   every character property and case mapping the port's py::text reproduces
'''
import argparse
import sys


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
    with open(out, 'w', encoding='utf-8') as f:
        f.write(dump)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    unicode_parser = sub.add_parser('unicode')
    unicode_parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.command == 'unicode':
        unicode_dump(args.out)


if __name__ == '__main__':
    sys.exit(main())
