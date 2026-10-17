"""The code-mode catalog fragment and its revision (ONE-2510 S2).

EIRI-ARCH-0002 §The contract teaches the catalog once in the cached prefix as
generated TypeScript definitions, and restates its revision after compaction.
ARCH-0044 S2 makes that catalog the whole verb set the one SDK table holds.
This module renders it from that table and the Rust types its rows name.

The text covers every row code mode serves, at its SDK path. These are the
host's rows (facade, host door, board and browser rows) and then the rows the
run answers itself, under the `self`/`vault`/`connector`/`ai`/`tasks` roots or
bare. Each row has its typed input and its typed reply. A row whose reply
turns on which input field is present (`outputs_by_input`) takes one overload
per such field, most specific first, then its own. Every type they reach is
written out once, nested types included, in one namespace. The types come
from the facade type inventory (`facade_types.Inventory`), walked here over
the code-mode rows. The facade's own TypeScript and Python outputs keep their
own inventory, so this module changes neither.

There is one text at two paths: `catalog_fragment.d.ts`, which the executor
teaches and its shadow check reads, and `code-mode.d.ts`, which the
code-check oracle fixtures and the hook contract stamp read. The engine's
`code_mode_declarations()` returns that same text. Neither file is written
by hand.

The revision is the digest of the text, written as a Rust constant beside it.
A change to the table or to a reached type changes all three files, and
`generate.py --check` flags any one that falls behind. The text is read back
before it is written: it must declare exactly the code-mode rows.
"""
import hashlib
import json
import re
from facade_types import Inventory, compound, ts_key

FRAGMENT = 'crates/oneiron/src/task_verb/catalog_fragment.d.ts'
CODE_MODE = 'crates/oneiron/src/task_verb/code-mode.d.ts'
REVISION = 'crates/oneiron/src/task_verb/catalog_fragment_revision.rs'

# The calls (canon silent), each in one place:
# - NAMESPACE: the one namespace every reached type sits in. Inside it no type
#   collides with a global that the other code-mode declarations name.
# - REVISION_ALGORITHM: the revision's digest and form, `sha256:<64 hex>` of
#   the UTF-8 text. Python's standard library has SHA-256; it has no BLAKE3.
# - REPLY: what a verb call resolves with in code mode, and what it throws.
#   The host writes `{output}`, `{denied, reasonCodes}`, `{failed, error?}`
#   (`error` only for a code in wire.rs `GUEST_FAILURE_CODES`) or, for a call
#   that parks and every call past a park, `{waitId}`, with `budget` added
#   inside a wake pass (wire.rs `reply_body`, `SelfDispatchResponse::guest_json`).
#   The guest's verb import takes `output` alone (code_sandbox/wasmtime_runtime/
#   typed.rs, `self.verbs.call`), and bootstrap.js `verb` resolves with it
#   decoded: the row's output, or `StoredResult`, runtime.d.ts's card, in its
#   place past 512 KiB of JSON (wire.rs `fit_reply`). A refusal throws its
#   whole JSON text (typed.rs `State::call`), a reply with no `output` throws
#   `missing_host_response_field` (typed.rs `field`), and `budget` never
#   reaches the guest.
# - COORDINATION: the rows code mode answers with the run's own coordination
#   reply, not the row's output (wire.rs `self_call`). Their reply is
#   `unknown`, and so is a run row's output when the table does not name it.
#   Today every row answers its output, `ask` and `wait` included.
# - JSDOC: each verb carries its row's one-line description as its JSDoc, as
#   every generated TypeScript method does.
# - VAULT_HOST: an empty interface in the namespace that the `vault` root
#   extends, so another declaration file can add members to it (the
#   executor's WIT-root members) by merging, and this text stays valid alone.
# - CONNECTOR_TOOLS: `connector.<name>.<tool>(args)`, any tool of any
#   catalogued connector beside the root's fixed members. The guest's proxy
#   sends it as `connector.call`, so it resolves with that row's reply.
NAMESPACE = 'Sdk'
REVISION_ALGORITHM = 'sha256'
REPLY = 'Promise<{output} | StoredResult>'
REPLY_DOC = (
    'Every verb call resolves with its row\'s output itself, or with a `StoredResult` card in its place past 512 KiB of JSON.',
    'A refused call throws a string, the refusal\'s JSON: JSON.parse gives `{denied, reasonCodes}` (`denied` the outcome word,',
    '`reasonCodes` a string[]) or `{failed: true, error?}` (`error` a stable code, such as "finding_not_own", when the host names one).',
    'A call that parks the run, and every call after a park, throws "missing_host_response_field"; the host bridge\'s own',
    'refusals throw a bare code too, such as "verb_input_over_budget" or "host_response_over_budget".',
)
COORDINATION = ()
JSDOC = True
VAULT_HOST = 'VaultHost'
VAULT_HOST_DOC = ('/** Members the `vault` root holds beside its verbs; another declaration file adds them '
                  'by merging into this interface. */')
CONNECTOR_TOOLS = '{{ readonly [name: string]: {{ readonly [tool: string]: (args?: object) => {result} }} }} & '
# `self.fold` is the one positional verb (ARCH-0067 #folds), as bootstrap.js
# takes it.
POSITIONAL = {'self.fold': '(span: readonly [number, number], options?: { note?: string | null })'}
# Names no reached type may take: the global the fragment names from inside
# the namespace, and the fragment's own interface.
TAKEN = ('StoredResult', VAULT_HOST)


class Fragment:
    'The catalog fragment over the code-mode rows: its text, census and revision.'

    def __init__(self, root, rows):
        self.rows = rows
        self.inventory = Inventory(root, [])
        self.inventory.names.update(TAKEN)
        for row in rows:
            self.inventory.root_ir(row['input'])
            if 'output' in row: self.inventory.root_ir(row['output'])
            for field, output in row.get('outputs_by_input', {}).items():
                if row['name'] in POSITIONAL: raise ValueError(f'{row["name"]}: a positional verb has no input field to select its reply')
                if field not in self.fields(row['input']):
                    raise ValueError(f'{row["name"]}: outputs_by_input names {field}, which its input {row["input"]} does not carry')
                self.inventory.root_ir(output)

    def ts(self, text):
        return self.inventory.ts_type(text, NAMESPACE + '.')

    def fields(self, text):
        'The wire field names of an input that reads as one object.'
        node = self.inventory.root_ir(text)
        if node[0] == 'ref': node = self.inventory.decls[node[1]]['ir']
        return {field[0] for field in node[1]} if node[0] == 'object' else set()

    def params(self, row):
        return POSITIONAL.get(row['name']) or f'(input: {self.ts(row["input"])})'

    def reply(self, text):
        output = self.ts(text) if text else 'unknown'
        return 'Promise<unknown>' if output == 'unknown' else REPLY.format(output=output)

    def result(self, row):
        if row['name'] in COORDINATION: return 'Promise<unknown>'
        return self.reply(row.get('output'))

    def signatures(self, row):
        'The row\'s call signatures, most specific first: one per input field whose presence selects its own reply, then its own.'
        own = (self.params(row), self.result(row))
        if 'outputs_by_input' not in row: return [own]
        base = self.ts(row['input'])
        if compound(base): base = f'({base})'
        return [(f'(input: {base} & {{ {ts_key(field)}: NonNullable<{base}[{json.dumps(field)}]> }})', self.reply(output))
                for field, output in row['outputs_by_input'].items()] + [own]

    def call(self, row):
        'The row as one call type: an arrow, or a call-signature literal over its overloads.'
        signatures = self.signatures(row)
        if len(signatures) == 1: return f'{signatures[0][0]} => {signatures[0][1]}'
        return '{ ' + ' '.join(f'{params}: {result};' for params, result in signatures) + ' }'

    def typed(self, row):
        'Whether the row\'s reply names its output type.'
        return row['name'] not in COORDINATION and 'output' in row

    # ---- verbs: `self` a namespace of constants, every other root a constant,
    # a bare verb a function, so a row named by a reserved word (`vault.export`)
    # is a valid method: a namespace's `function export` does not parse.

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
        call = self.call(row) if row else None
        if not node['children']: return call or '{}'
        members = '{\n' + self.members(node['children'], depth + 1) + '  ' * depth + '}'
        return f'({call}) & {members}' if call else members

    def members(self, children, depth):
        indent, out = '  ' * depth, ''
        for name in sorted(children):
            node = children[name]
            out += self.doc(node, indent)
            if node['row'] and not node['children']:
                out += ''.join(f'{indent}{name}{params}: {result};\n' for params, result in self.signatures(node['row']))
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
                out += self.doc(node, '') + ''.join(f'declare function {root}{params}: {result};\n' for params, result in self.signatures(node['row']))
            else:
                out += self.doc(node, '') + f'declare const {root}: {self.extends(root, node)}{self.kind(node, 0)};\n'
        return out

    def extends(self, root, node):
        'What a root\'s constant extends beside its own members.'
        if root == 'vault':
            return f'{NAMESPACE}.{VAULT_HOST} & '
        call = node['children'].get('call')
        if root == 'connector' and call and call['row']:
            return CONNECTOR_TOOLS.format(result=self.result(call['row']))
        return ''

    # ---- the text

    def census(self):
        run = sum(1 for row in self.rows if 'call' not in row)
        states = {}
        for row in self.rows:
            state = self.inventory.root_state(row['output']) if self.typed(row) else 'unnamed'
            states[state] = states.get(state, 0) + 1
        by_input = {}
        for row in self.rows:
            for output in row.get('outputs_by_input', {}).values():
                state = self.inventory.root_state(output)
                by_input[state] = by_input.get(state, 0) + 1
        unread = sorted({where for where, _, _ in self.inventory.fallbacks})
        return [
            f'Census: {len(self.rows)} code-mode rows ({len(self.rows) - run} host rows, {run} run rows), '
            f'{len(self.inventory.decls)} declarations.',
            f'Replies: {states.get("typed", 0)} fully typed, {states.get("opaque", 0)} typed down to an opaque '
            f'serde_json::Value leaf, {states.get("unknown", 0)} with a shape the generator could not read, '
            f'{states.get("unnamed", 0)} unknown (rows whose output the table does not name, or the run\'s own coordination reply).',
            f'Per-input replies: {sum(by_input.values())} ({by_input.get("typed", 0)} fully typed, {by_input.get("opaque", 0)} typed '
            f'down to an opaque serde_json::Value leaf, {by_input.get("unknown", 0)} with a shape the generator could not read).',
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
        out += ''.join('// ' + line + '\n' for line in REPLY_DOC)
        out += ''.join('// ' + line + '\n' for line in self.census())
        out += f'declare namespace {NAMESPACE} {{\n'
        out += '  ' + VAULT_HOST_DOC + '\n  interface ' + VAULT_HOST + ' {}\n'
        for key in self.inventory.order:
            decl = self.inventory.decls[key]
            params = '<' + ', '.join(decl['params']) + '>' if decl['params'] else ''
            out += f'  type {decl["name"]}{params} = {self.inventory.ts(decl["ir"])};\n'
        out += '}\n'
        return out + self.verbs()


def revision(text):
    'The revision of a fragment text: its digest, named by its algorithm.'
    return REVISION_ALGORITHM + ':' + hashlib.new(REVISION_ALGORITHM, text.encode()).hexdigest()


# A line of the verb layout opens a root or a namespace, declares a verb, or
# both: `declare namespace self {`, `declare const ai: {`, `declare function
# describe(input: …`, `const fold: (span: …`, `update(input: …`, a verb that
# holds verbs `video: ((input: …) => …) & {`, or an overload literal
# `{ (input: …): …; … }`. `connector`'s tool index `{ readonly [name: …` is
# no verb.
LAYOUT_LINE = re.compile(r'(?:declare (?:namespace|const|function) |const )?(\w+)(\(|: | \{$)')


def declared(text):
    'The verb paths a fragment text declares, read back from its verb layout past the type namespace.'
    names, scope = set(), []
    types = text.index(f'declare namespace {NAMESPACE} {{\n')
    for line in text[text.index('\n}\n', types) + 3:].splitlines():
        line = line.strip()
        if line in ('}', '};'):
            scope.pop(); continue
        head = LAYOUT_LINE.match(line)
        if not head: continue
        name, form = head.groups()
        if form == '(' or line[head.end():].startswith(('(', '{ (')): names.add('.'.join(scope + [name]))
        if line.endswith('{'): scope.append(name)
    return names


def catalog_fragment(root, rows, header):
    'The fragment, at both its paths, and its revision constant: the files `generate.py` writes and checks.'
    text = Fragment(root, rows).text()
    differ = declared(text) ^ {row['name'] for row in rows}
    if differ: raise ValueError('the catalog fragment must declare exactly the code-mode rows; it differs at ' + ', '.join(sorted(differ)))
    constant = (header + '/// The code-mode catalog fragment\'s revision: `' + REVISION_ALGORITHM + ':` and the hex\n'
                '/// digest of `catalog_fragment.d.ts`, so it changes exactly when that text does.\n'
                f'pub const CATALOG_FRAGMENT_REVISION: &str = {json.dumps(revision(text))};\n')
    return {FRAGMENT: text, CODE_MODE: text, REVISION: constant}
