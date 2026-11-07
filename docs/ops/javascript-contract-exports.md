# JavaScript and TypeScript contract exports

A merge-queue check plan declares public entries under `contracts.js_modules`.
Each map key is a stable public entry name. Its value is a source file relative to
that check's materialized worktree. For example:

```json
"contracts": {
  "rust_crates": {},
  "js_modules": { "package-api": "src/index.ts" },
  "schemas": {},
  "outputs": []
}
```

`js_modules` is a required field, including when empty. There is no old-plan reader.
The existing baseline identity includes the complete spec and captured snapshot.
The ordinary queue capture still checks the worktree before and after observation.
No source code is executed by export extraction.

## Names and re-exports

Oxc 0.152 parses `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts` and `.tsx`
using its extension-specific source mode. Its normalized explicit export names
include named declarations, destructured bindings, aliases, string names,
TypeScript type exports, default exports (including anonymous expressions,
functions and classes) and namespace exports. Private symbols
and side-effect imports do not become public names.

Names are `js:<entry-name>::<export-name>`. The declared entry name, not an
implementation filename, is the public identity. Moving its source file does not
by itself remove its exports. Name segments percent-escape `%`, `:` and `#`, so
entry/export delimiters cannot collapse two different names. Rust name spelling
is unchanged. TypeScript `export =` is recorded as unresolved, not treated as an
observed empty surface.

Relative re-exports follow exact files within the worktree. Paths normalize
relative `.` and `..` components without escaping the root. The existing resolver
still rejects symlinks and git-administration paths. There is no package lookup,
network access, extension substitution, directory-index search or tsconfig alias
resolution. Bare, missing and otherwise unresolved targets are recorded in
`ContractSnapshot.unresolved_exports`; their members are not guessed.

Local `export *` graphs use a finite worklist, including cycles. Star exports
exclude `default`. Explicit exports override stars. Two paths to the same original
binding remain one export; different bindings with the same star-exported name
are recorded as unresolved, not advertised as a public name. An explicitly named
external re-export keeps its declared alias and also records the unresolved target.
A local named re-export with no reachable binding is unresolved.

## Direct CommonJS declarations

For CommonJS, the extractor recognizes top-level direct assignments to
`module.exports`, `module.exports.name`, `module.exports["name"]`, `exports.name`
and `exports["name"]`. Top-level comma expressions apply those same direct
assignment and delete rules in left-to-right order, including nested comma
expressions. They share the ordinary wrapper and alias state. Direct chains such
as `exports.a = exports.b = 1` contribute every eligible named property when all
links are plain assignments to the current wrapper export object. Whole-module
or wrapper-identifier assignments, unknown computed keys, `__proto__`, compound
operators and sequence-valued terminals keep the ordinary outer-only handling and
unresolved sites. The terminal value is not evaluated; its unknown wrapper
references still produce unresolved sites. No conditional expressions are evaluated.
Uninitialized root `var module` and `var exports` redeclare the CommonJS wrapper
parameters, including hoisted or repeated redeclarations. Direct simple `var`
initializers update the same alias state in
source order. Lexical and function shadows remain distinct from wrapper bindings.
Destructured, conditional and loop-carried initializer flows are not modeled.
A direct `module = module` or `var module = module` preserves its current
wrapper identity; assigning an unrelated value does not. This does not infer
arbitrary alias identities. Rebinding `exports` does not replace the module value. Replacing
`module.exports` detaches its old `exports` alias; an explicit reassignment to the
current module value reconnects it. Whole object-literal replacements contribute
static own keys and replace the preceding declared keys. A colon `__proto__`
property sets a prototype, not an own key. A direct `.__proto__` assignment is
unresolved unless a preceding literal already established that own key; the
inherited prototype setter alone does not certify an export.

CommonJS supplies a `default` whole-module value. This name is present for explicit
CommonJS source modes, or when a recognized direct wrapper export establishes
CommonJS in an unambiguous `.js`/`.ts` source. Ordinary ESM never gets that name
merely because the file has no exports.

This is a syntactic declared surface, not runtime object evaluation. Computed
keys, object spreads, opaque whole values and other wrapper references record
unresolved sites. Direct top-level deletes remove their declared keys.
Conditional/nested mutations, reflective calls, alias flows and package resolution
are not a complete surface proof.
The lexical CommonJS symbol graph is independent: its private bindings and
calls/refs/imports are not used as public exports.

## Capture and removal

Capture adds these names and unresolved sites to the existing snapshot beside
Rust, schema and command observations. A missing captured name produces the same
`ContractDiff::RemovedPublicName` as Rust. No new verdict variant, acceptance rule,
review permission or merge-queue door is introduced. The separately implemented
removed-name person-review route remains responsible for routing that diff.

Syntax, binding and file-read failures remain errors, never successful empty
observations. There is no new source-size cap, depth cap or file-count cap. Existing
schema, row, authority and worktree checks are unchanged. Unresolved sites remain
records under the existing oracle behavior, not new refusals. Their presence is
not a claim that the complete runtime API was observed.
