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
links are plain assignments to the current wrapper export object. Mixed replacement
chains such as `module.exports = exports = {a: 1}` and
`exports = module.exports = {a: 1}` also contribute the literal's static own keys.
Every link must be a plain assignment to either the native `module.exports` slot or
the wrapper `exports` binding, both kinds must occur, and the terminal must be an
object literal, function expression, arrow function or class expression. Both slots
receive that same value, so later `exports.b` assignments refer to the new module
value. Only object literals contribute interior declared keys; function and class
members are not inferred. References are collected before applying
the chain; no admitted link rebinds `module` or targets a property of the replaced
value. The literal uses the ordinary own-key, spread and `__proto__` rules.
Repeated whole-slot chains such as `module.exports = module.exports = {a: 1}`
also use one fresh terminal value and contribute its declared keys once. They require
at least two plain-assignment links. Without an actual wrapper `exports` assignment,
the old `exports` binding remains detached; a repeated whole store does not reconnect it.
A chain containing only wrapper `exports` assignments keeps its ordinary handling.

Stable whole-slot/wrapper chains may also return the already-current module value.
For `module.exports = module.exports = module.exports`, the declared keys and existing
wrapper alias are preserved. Adding an actual `exports` assignment, as in
`exports = module.exports = module.exports`, reconnects that wrapper to the current
module without clearing its keys. A terminal `exports` reference qualifies only when
that wrapper already aliases the current module. These are direct native identity
checks, not arbitrary alias inference; a current value is not a fresh replacement.

Mixed chains can also contain eligible named properties of the current module value.
Each property receiver is captured before the right-hand side, and all stores use
the same terminal value in inner-to-outer order. For
`exports.a = (exports = {})`, `a` remains on the original module value while later
`exports.b` is detached. For `exports.a = (module.exports = {x: 1})`, the `a` write
targets the old object, so only `x` belongs to the new module value. Repeated whole
stores receive that same value, rather than inventing another replacement object.
These chains require at least one eligible static named-property reference and one
whole-slot or wrapper-binding assignment. A property reference must resolve to the
current module value at capture time; detached `exports` properties, `__proto__`
property assignments and unknown computed receivers retain the ordinary fallback.

Captured-property chains can also return the proven current module value. Their
whole stores preserve the existing keys, and every captured property still targets
that same current object. An actual wrapper `exports` assignment reconnects it;
otherwise its existing alias is preserved. A terminal `module.exports` must still
use the native `module` binding, and terminal `exports` must already alias the
current module. Rebinding `module` does not prove its new value is the native module.

A direct whole-slot assignment can also contain a flat comma-valued right-hand
side such as `module.exports = (module.exports = {a: 1}, module.exports)`.
Every non-final element must be a plain native whole-slot assignment with an
object literal, function expression, arrow function or class expression value;
the final element must read the native `module.exports` slot or supply another
of those fresh expressions. For example,
`module.exports = (module.exports = {a: 1}, {b: 2})` keeps only `b` from the final
outer replacement. The outer slot is captured before the right-hand side.
Replacements apply in source order, including
each value's unresolved spread or computed-key sites, and the outer store keeps
the last replacement's keys. The old wrapper `exports` binding remains detached.
The entire sequence must qualify before any of these effects or reference
accounting is applied. A final `exports` reference does not qualify after fresh
replacements, because an inner replacement can already have detached it.

The same flat form also accepts an identity-only prefix, such as
`module.exports = (module.exports = module.exports, module.exports)`.
Every prefix assignment must read the current native whole slot or the wrapper
`exports` binding when it already aliases that current value. The final element
must read the same slot or that already-aliased wrapper. For example,
`module.exports = (module.exports = exports, module.exports)` preserves the
current value when `exports` already aliases it. Either current-valued final
preserves the declared keys and the existing wrapper alias; it neither replaces
the value nor reconnects a detached `exports` binding. A fresh final expression
instead replaces the current value once. For example,
`module.exports = (module.exports = module.exports, {b: 2})` contributes `b` and
detaches the old wrapper alias. The same object-literal, function, arrow and class
rules apply to that final value, including unresolved interior references.
Fresh values and current native whole-slot reads may also appear in the same
flat prefix. Every fresh value is processed in source order, including its
unresolved interior references. Reading the current slot between replacements
keeps that value unchanged. A prefix `exports` read still requires the original
alias and must occur before the first fresh replacement. Reading that old wrapper
after a replacement keeps the ordinary fallback; its old keys are not restored.

For a whole-slot outer assignment, the final element may itself be another
plain native whole-slot assignment. For example,
`module.exports = (module.exports = {a: 1}, module.exports = {b: 2})` keeps `b`.
That final store uses the same prefix checks and ordered fresh-value handling;
the outer store writes the value that was just stored. A current-valued final
store preserves that current value. Detached-wrapper, named-property, rebinding,
compound and unknown-value final stores keep the ordinary fallback.

A direct assignment to the wrapper `exports` binding can use that same flat
prefix when the final element reads the native `module.exports` slot. For example,
`exports = (module.exports = {a: 1}, module.exports)` contributes `a` and reconnects
that wrapper to the current module value. Fresh prefix values still apply in
source order, including their unresolved interior references. An all-current
prefix preserves the declared keys and reconnects the wrapper. A fresh final or
an `exports` final does not qualify for this binding form: assigning a fresh value
to `exports` alone would not replace the module value. The final element may instead
be another qualifying plain native whole-slot assignment. For example,
`exports = (module.exports = {a: 1}, module.exports = {b: 2})` applies both
replacements and reconnects the wrapper to the current module value containing `b`. The final store
uses the same whole-slot prefix checks; property, wrapper-binding, compound and
unknown-value stores keep the ordinary fallback.

Other whole-module or wrapper-identifier chains, unknown computed keys, `__proto__`
property assignments, compound operators and other sequence-valued terminals keep
the ordinary outer-only handling and unresolved sites. Terminal values are not executed;
their unknown wrapper references still produce unresolved sites, including references
inside function bodies, class heritage, computed class keys and static initializers
or blocks. Those sites do not supply inferred runtime properties. No conditional
expressions are evaluated.
Uninitialized root `var module` and `var exports` redeclare the CommonJS wrapper
parameters, including hoisted or repeated redeclarations. Direct simple `var`
initializers update the same alias state in
source order. A direct root `var exports` initializer can also use the same flat
whole-slot prefix when its final element reads the current native module slot,
such as `var exports = (module.exports = {a: 1}, module.exports)`, or makes another
qualifying plain whole-slot assignment. It applies the fresh prefix values in
order and reconnects that actual wrapper binding; an all-current prefix preserves
keys. Fresh or `exports` final values retain the ordinary initializer handling. A direct root `var module` initializer can use
that same flat whole-slot prefix when its final element reads the native `module`
object itself, as in `var module = (module.exports = {a: 1}, module)`. Fresh prefix
values apply in source order and detach the old `exports` alias; an all-current
prefix preserves keys and alias. The `module` binding stays native because the
final read returns the same original module object, not the current exported value.
A direct plain assignment to the native wrapper `module` binding uses the same
module-object final rule, as in `module = (module.exports = {a: 1}, module)`.
Its prefix replacements apply in order without rebinding the module object;
only fresh replacements detach the old `exports` alias. A final export value,
fresh value or assignment does not qualify for either module-binding form.
Lexical and function shadows remain distinct from wrapper bindings. Destructured,
conditional and loop-carried initializer flows are not modeled.
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
