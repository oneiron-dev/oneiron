#!/usr/bin/env python3
"""The SDK's public surface and its drift (untangle slice 4.3; SLICE4-RULED S4-6 = a).

The surface is what an SDK user names: every facade verb (a verb-table row in the memory context, as the verb
census counts them), its input and output types, and the SDK packages' major versions. The generated SDK files are
not in git, so a pull request shows this summary instead of their diff.

    surface.py                     print the surface of the working tree (JSON)
    surface.py --diff BASE         print what changed between BASE and the working tree; never fails
    surface.py --enforce           after the first `v*` tag: compare with the newest one, and fail on a removed
                                   verb or a changed input type unless an SDK major moved; before it, report only

Before the first release the step only reports: the owner's rule is no backward compatibility before release.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERBS = 'scripts/sdk/verbs'
# Before slice 4.2 the verb table was one file.
TABLE = 'scripts/sdk/agent-verbs.json'
PACKAGES = {
    'oneiron (npm)': 'packages/oneiron/package.json',
    '@oneiron/client (npm)': 'packages/oneiron-client/package.json',
    'oneiron (PyPI)': 'crates/oneiron-py/Cargo.toml',
}


def git(*args):
    result = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def read(ref, path):
    'A file at `ref`, or in the working tree when `ref` is None; None when it is absent.'
    if ref is None:
        p = ROOT / path
        return p.read_text() if p.is_file() else None
    return git('show', f'{ref}:{path}')


def verb_rows(ref):
    if ref is None:
        return [json.loads(p.read_text()) for p in sorted((ROOT / VERBS).glob('*.json'))]
    names = git('ls-tree', '--name-only', f'{ref}:{VERBS}')
    if names:
        return [json.loads(read(ref, f'{VERBS}/{name}')) for name in sorted(names.split()) if name.endswith('.json')]
    table = read(ref, TABLE)
    return json.loads(table)['verbs'] if table else []


def major(text, path):
    if text is None:
        return None
    if path.endswith('.json'):
        version = json.loads(text).get('version', '')
    else:
        found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
        version = found[1] if found else ''
    return version.split('.')[0] or None


def surface(ref=None):
    verbs = {row['name']: {'input': row.get('input'), 'output': row.get('output')}
             for row in verb_rows(ref) if row.get('context', 'memory') == 'memory'}
    majors = {name: major(read(ref, path), path) for name, path in PACKAGES.items()}
    return {'verbs': verbs, 'majors': majors}


def drift(old, new):
    removed = sorted(set(old['verbs']) - set(new['verbs']))
    added = sorted(set(new['verbs']) - set(old['verbs']))
    both = sorted(set(old['verbs']) & set(new['verbs']))
    inputs = [(name, old['verbs'][name]['input'], new['verbs'][name]['input'])
              for name in both if old['verbs'][name]['input'] != new['verbs'][name]['input']]
    outputs = [(name, old['verbs'][name]['output'], new['verbs'][name]['output'])
               for name in both if old['verbs'][name]['output'] != new['verbs'][name]['output']]
    majors = [(name, old['majors'].get(name), new['majors'].get(name))
              for name in PACKAGES if old['majors'].get(name) != new['majors'].get(name)]
    return removed, added, inputs, outputs, majors


def report(label, old, new):
    removed, added, inputs, outputs, majors = drift(old, new)
    lines = [f'SDK public surface, {label}: {len(old["verbs"])} -> {len(new["verbs"])} facade verbs']
    lines += [f'  removed verb: {name}' for name in removed]
    lines += [f'  added verb: {name}' for name in added]
    lines += [f'  input type changed: {name}: {a} -> {b}' for name, a, b in inputs]
    lines += [f'  output type changed: {name}: {a} -> {b}' for name, a, b in outputs]
    lines += [f'  SDK major: {name}: {a} -> {b}' for name, a, b in majors]
    if len(lines) == 1:
        lines.append('  no change')
    print('\n'.join(lines))
    return removed, inputs, majors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--diff', metavar='BASE', help='a git ref to compare the working tree with')
    parser.add_argument('--enforce', action='store_true', help='compare with the newest v* tag, once one exists')
    args = parser.parse_args()
    head = surface()
    if args.diff is not None:
        if not args.diff or git('rev-parse', '--verify', '--quiet', f'{args.diff}^{{commit}}') is None:
            print(f'SDK public surface: no base commit {args.diff!r} here; nothing to compare')
        else:
            report(f'{args.diff[:12]} -> working tree', surface(args.diff), head)
    if args.enforce:
        tags = (git('tag', '--list', 'v*', '--sort=-v:refname') or '').split()
        if not tags:
            print('SDK public surface: no v* tag yet, so the drift is reported, never enforced (S4-6 a)')
        else:
            removed, inputs, majors = report(f'{tags[0]} -> working tree', surface(tags[0]), head)
            if (removed or inputs) and not majors:
                print(f'SDK-SURFACE-BREAK: a verb was removed or an input type changed since {tags[0]} '
                      'with no SDK major change', file=sys.stderr)
                return 1
    if args.diff is None and not args.enforce:
        print(json.dumps(head, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
