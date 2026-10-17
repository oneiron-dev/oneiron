"""The code-mode catalog fragment and its revision (ONE-2510 S2).

EIRI-ARCH-0002 §The contract teaches the catalog once in the cached prefix as
generated TypeScript definitions, and restates its revision after compaction.
ARCH-0044 S2 makes that catalog the whole verb set the one SDK table holds.
This module renders it from that table and the Rust types its rows name.

The text covers every row code mode serves, at its SDK path. These are the
host's rows (facade, host door, board and browser rows) and then the rows the
run answers itself, under the `self`/`vault`/`connector`/`ai`/`tasks` roots or
bare. Each row has its typed input and its typed reply. Every type they reach
is written out once, nested types included, in one namespace. The types come
from the facade type inventory (`facade_types.Inventory`), walked here over
the code-mode rows. The facade's own TypeScript and Python outputs keep their
own inventory, so this module changes neither. Verbs are laid out as the
engine's `code_mode_declarations()` lays them out, so either text can stand
for the other.

The revision is the digest of the text, written as a Rust constant beside it.
A change to the table or to a reached type changes both, and
`generate.py --check` flags either one when it falls behind.
"""
import hashlib
import json
from facade_types import Inventory

FRAGMENT = 'crates/oneiron/src/task_verb/catalog_fragment.d.ts'
REVISION = 'crates/oneiron/src/task_verb/catalog_fragment_revision.rs'

# The calls (canon silent), each in one place:
# - NAMESPACE: the one namespace every reached type sits in. Inside it no type
#   collides with a global that the other code-mode declarations name.
# - REVISION_ALGORITHM: the revision's digest and form, `sha256:<64 hex>` of
#   the UTF-8 text. Python's standard library has SHA-256; it has no BLAKE3.
# - REPLY: what a verb call resolves with in code mode. The guest's verb door
#   decodes the host's whole reply (components/code-run-quickjs/bootstrap.js,
#   `verb`), and the host writes it as `{output}`, `{denied, reasonCodes}`,
#   `{failed}` or, for a call that parks and every call past a park,
#   `{waitId}`, with `budget` added inside a wake pass (wire.rs `reply_body`,
#   `SelfDispatchResponse::guest_json`). `StoredResult` is runtime.d.ts's card,
#   which stands in for an output past 512 KiB of JSON.
# - COORDINATION: the rows code mode answers with the run's own coordination
#   reply, not the row's output (wire.rs `self_call`). Their reply is
#   `unknown`, and so is a run row's output when the table does not name it.
#   Today every row answers its output, `ask` and `wait` included.
# - JSDOC: each verb carries its row's one-line description as its JSDoc, as
#   every generated TypeScript method does.
NAMESPACE = 'Sdk'
REVISION_ALGORITHM = 'sha256'
REPLY = ('type Reply<T> = ({ output: T | StoredResult } | { denied: string; reasonCodes: string[] } | { failed: true } '
         '| { waitId: string }) & { budget?: {budget} };')
REPLY_DOC = ('/** What a verb call resolves with: its `output`, a `StoredResult` card in its place past 512 KiB of JSON, '
             'the refusal it met, or the wait the run parked on; `budget` rides on every reply inside a wake pass. */')
BUDGET = 'crate::dreamer_wake::legibility::BudgetLegibilityEnvelope'
COORDINATION = ()
JSDOC = True
# `self.fold` is the one positional verb (ARCH-0067 #folds), as
# `code_mode_declarations()` and bootstrap.js take it.
POSITIONAL = {'self.fold': '(span: readonly [number, number], options?: { note?: string | null })'}
# Names no reached type may take: the fragment's own reply type, and the global
# it names from inside the namespace.
TAKEN = ('Reply', 'StoredResult')


class Fragment:
    'The catalog fragment over the code-mode rows: its text, census and revision.'

    def __init__(self, root, rows):
        self.rows = rows
        self.inventory = Inventory(root, [])
        self.inventory.names.update(TAKEN)
        for row in rows:
            self.inventory.root_ir(row['input'])
            if 'output' in row: self.inventory.root_ir(row['output'])
        self.budget = self.inventory.ts_type(BUDGET, '')

    def ts(self, text):
        return self.inventory.ts_type(text, NAMESPACE + '.')

    def params(self, row):
        return POSITIONAL.get(row['name']) or f'(input: {self.ts(row["input"])})'

    def result(self, row):
        if row['name'] in COORDINATION: return 'Promise<unknown>'
        output = self.ts(row['output']) if 'output' in row else 'unknown'
        return f'Promise<{NAMESPACE}.Reply<{output}>>'

    def typed(self, row):
        'Whether the row\'s reply names its output type.'
        return row['name'] not in COORDINATION and 'output' in row

    # ---- verbs, laid out as `code_mode_declarations()` lays them out

    def tree(self):
        root = {'row': None, 'children': {}}
        for row in self.rows:
            node = root
            for part in row['name'].split('.'):
                node = node['children'].setdefault(part, {'row': None, 'children': {}})
            node['row'] = row
        return root['children']

    @staticmethod
    def doc(node, indent):
        row = node['row']
        return f'{indent}/** {row["description"]} */\n' if JSDOC and row and row.get('description') else ''

    def kind(self, node, depth):
        'A path segment\'s type: its call signature, the members it holds, or both at once.'
        row = node['row']
        call = f'{self.params(row)} => {self.result(row)}' if row else None
        if not node['children']: return call or '{}'
        members = '{\n' + self.members(node['children'], depth + 1) + '  ' * depth + '}'
        return f'({call}) & {members}' if call else members

    def members(self, children, depth):
        indent, out = '  ' * depth, ''
        for name in sorted(children):
            node = children[name]
            out += self.doc(node, indent)
            if node['row'] and not node['children']:
                out += f'{indent}{name}{self.params(node["row"])}: {self.result(node["row"])};\n'
            else:
                out += f'{indent}{name}: {self.kind(node, depth)};\n'
        return out

    def verbs(self):
        out, tree = '', self.tree()
        for root in sorted(tree):
            node = tree[root]
            if root == 'self':
                out += 'declare namespace self {\n'
                for name in sorted(node['children']):
                    child = node['children'][name]
                    out += self.doc(child, '  ') + f'  const {name}: {self.kind(child, 1)};\n'
                out += '}\n'
            elif node['row'] and not node['children']:
                out += self.doc(node, '') + f'declare function {root}{self.params(node["row"])}: {self.result(node["row"])};\n'
            else:
                out += self.doc(node, '') + f'declare const {root}: {self.kind(node, 0)};\n'
        return out

    # ---- the text

    def census(self):
        run = sum(1 for row in self.rows if 'call' not in row)
        states = {}
        for row in self.rows:
            state = self.inventory.root_state(row['output']) if self.typed(row) else 'unnamed'
            states[state] = states.get(state, 0) + 1
        unread = sorted({where for where, _, _ in self.inventory.fallbacks})
        return [
            f'Census: {len(self.rows)} code-mode rows ({len(self.rows) - run} host rows, {run} run rows), '
            f'{len(self.inventory.decls)} declarations.',
            f'Replies: {states.get("typed", 0)} fully typed, {states.get("opaque", 0)} typed down to an opaque '
            f'serde_json::Value leaf, {states.get("unknown", 0)} with a shape the generator could not read, '
            f'{states.get("unnamed", 0)} unknown (rows whose output the table does not name, or the run\'s own coordination reply).',
            f'Opaque serde_json::Value leaves: {len(self.inventory.opaques)}; unread shapes: '
            + (', '.join(unread) if unread else 'none') + '.',
        ]

    def text(self):
        out = '// Generated by scripts/sdk/generate.py from scripts/sdk/agent-verbs.json and the\n'
        out += '// Rust types its rows name; edit the table or the types instead.\n'
        out += '// The code-mode catalog: every verb code mode serves, at its SDK path, with its\n'
        out += f'// typed input and reply. `{NAMESPACE}` holds every type they reach; `StoredResult` is\n'
        out += '// runtime.d.ts\'s. The revision, the digest of this text, is\n'
        out += '// `CATALOG_FRAGMENT_REVISION` (catalog_fragment_revision.rs).\n'
        out += ''.join('// ' + line + '\n' for line in self.census())
        out += f'declare namespace {NAMESPACE} {{\n'
        out += '  ' + REPLY_DOC + '\n  ' + REPLY.replace('{budget}', self.budget) + '\n'
        for key in self.inventory.order:
            decl = self.inventory.decls[key]
            params = '<' + ', '.join(decl['params']) + '>' if decl['params'] else ''
            out += f'  type {decl["name"]}{params} = {self.inventory.ts(decl["ir"])};\n'
        out += '}\n'
        return out + self.verbs()


def revision(text):
    'The revision of a fragment text: its digest, named by its algorithm.'
    return REVISION_ALGORITHM + ':' + hashlib.new(REVISION_ALGORITHM, text.encode()).hexdigest()


def catalog_fragment(root, rows, header):
    'The fragment and its revision constant, by path: the files `generate.py` writes and checks.'
    text = Fragment(root, rows).text()
    constant = (header + '/// The code-mode catalog fragment\'s revision: `' + REVISION_ALGORITHM + ':` and the hex\n'
                '/// digest of `catalog_fragment.d.ts`, so it changes exactly when that text does.\n'
                f'pub const CATALOG_FRAGMENT_REVISION: &str = {json.dumps(revision(text))};\n')
    return {FRAGMENT: text, REVISION: constant}
