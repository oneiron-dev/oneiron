# CommonJS symbol extraction

Repository capture and secret-mask refresh derive code symbols from the same
retained, masked source text. Rust keeps its tree-sitter extraction. Files ending
in `.cjs` use the existing OXC JavaScript parser in CommonJS mode, with semantic
binding analysis. No code is executed during extraction.

## Recorded facts

- A parsed file has a `<module>` symbol. Lexical function, class and variable
  bindings have their actual declaration spans, file-document identity and ordinal.
- `calls` links a source function/class, or its file module, to a lexically resolved
  binding used directly as a call or constructor callee.
- `refs` links that same source to a resolved read that is not a direct callee.
- `imports` links a source to a successfully parsed file in the same capture when
  an unshadowed, unreassigned `require` has one literal relative specifier naming
  that exact file. `..` is resolved relative to the importing file, not the host.
  External packages, dynamic specifiers and missing files do not produce an
  import edge; a file module does not link to itself. In particular, extensionless require does not guess
  a `.cjs` suffix; Node's extension search does not do that either.

These are static source facts, not runtime call traces or authority. Calls through
properties, higher-order values or exported aliases are not resolved to a remote
implementation. References inside `with` have no inferred lexical target. A
CommonJS file with syntax diagnostics keeps its imported blob but contributes no
new symbols. It cannot turn an otherwise accepted repository import into a refusal.

## Storage and reads

Symbols use the existing manifest/chunk encoding, document/name/kind/ordinal
identity, masked source, producing-operation lookup and grouped graph writer.
Identical declaration chunks are shared, including the module/declaration overlap
and destructured bindings. New relations are distinct from Rust's existing
`mentions` and `attached` edges; those edges are not reinterpreted as calls.

`calls`, `imports` and `refs` are structural relations with stored weight `1.0`.
They do not enter the shared-vault PPR walk. Existing weights, traversal budgets,
public edge-door policy and Rust behavior are unchanged. The new numeric
assignments are `calls=32`, `imports=33`, `refs=34`.

Existing owner and run definitions doors serve the new symbols through their
current snapshot and grant checks. This does not add a relation-neighbors verb or
claim that the old global PPR query is repository/version/caller-scoped. That
consumer and pinned-manifest citations remain separate work.

## Remaining scope

FIX 4302 remains partial: method/export identities and cross-file export/binding
resolution, dynamic targets and CJS semantic-diff/embedding support are not claimed
here. FIX 4303 remains open for relation-typed neighbors admitted before traversal,
ranking and counts, with citations tied to the pinned snapshot and content hash.
No tests, runtime execution, image build or deployment are part of this change.
