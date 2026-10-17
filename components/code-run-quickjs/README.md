# Plain-JavaScript QuickJS component

This is the real QuickJS interpreter, compiled to WASM. It does not interpret JS
with the host's Node, V8, or native QuickJS. It does not run WAT fixture programs.
The canonical ABI is `oneiron:code-run/guest@1.0.0` in
`crates/oneiron/wit/code-run.wit`.

## Build

The script never installs tools. The build host needs:

- wasi-sdk 27, with `WASI_SDK_PATH` pointing at its root;
- `wit-bindgen 0.46.0`;
- `wasm-tools 1.239.0`;
- Python 3.11 or newer.

Use the repository's assigned build host and target budget. Do not run a second
build in another writer's target directory. From the repository root:

```text
python3 components/code-run-quickjs/build.py --out target/code-run-quickjs
```

An offline build can add `--source /path/to/quickjs-2025-09-13-2.tar.xz`.
The only downloaded input is the source archive at
`https://bellard.org/quickjs/quickjs-2025-09-13-2.tar.xz`, pinned to SHA-256
`996c6b5018fc955ad4d06426d0e9cb713685a00c825aa5c0418bd53f7df8b0b4`.
Its MIT license must travel with a distributed component. The libc platform wrappers return empty arguments/environment and refuse all
I/O, ambient clocks and entropy entirely inside the guest. They expose no host
capability. No quickjs-libc,
module loader, native library loader, network, filesystem, environment, clock,
or random WASI interface is linked. The build rejects any core import module
other than `$root`; it does not add a WASI adapter to make such an import work.

The build emits:

- `quickjs-first-party.wasm`: all 15 typed imports;

- `quickjs-foreign.wasm`: only the six non-write imports;
- `quickjs-hook.wasm`: the hook guest (below), world `oneiron:hook/hook@1.0.0`
  from `crates/oneiron/wit/hook/hook.wit`, with its own three imports;
- `manifest.json`: source, WIT, toolchain and artifact pins.

The foreign WIT file is a generated import projection of the same world, not
another protocol. `run-step` and every record/variant stay byte-identical.
Do not install the first-party artifact in a foreign VM. The foreign linker
refuses it before guest code runs.

The checked-in `components/code-run-quickjs/artifacts/` contains the three component
files, the emitted manifest and upstream LICENSE. A second controlled build in
a different output directory produced byte-identical component SHA-256 values.
For each source change, rebuild and replace all five files together.
Review the binary SHA-256 values. Deploy those exact bytes and pass their pin
to `QuickJsRuntimeFactory::from_component`. The loader rejects WAT, wrong pins,
wrong exports/imports and a failed real-JS readiness probe. There is no fallback.
No artifact hash is claimed before the controlled build actually produces it.

## Runtime contract

`run-step(source)` executes plain JS in an async function. Top-level `await`,
closures, objects, arrays, regexps, BigInt and promises are interpreter features.
Each call creates a new QuickJS heap; each host step creates a new Store.
`Date` uses the typed frozen host clock and UTC. `Math.random` uses typed host
random bytes. Both seeds and step sequence are host-owned. A guest cannot obtain
ambient entropy through the initial QuickJS PRNG seed.

`console.log(...)` produces the next observation. `finish(value)` marks a
completed step, and a later call replaces its answer.
`writeOutput('/mnt/outputs/name', bytes)` appends to an output file, so a large
file is written in pieces. None of them holds a result whole or charges a size
budget: each streams to the host as it is written, through the hidden
`output-text` and `output-bytes` imports, in frames of at most one 1 MiB
message (text cut at a UTF-16 boundary, a lone surrogate sent as U+FFFD). The
host keeps each body in the vault's result store and gives the model a handle
and a preview.
First-party code also gets `store(value, name?)`, which streams a value the
same way (a string as given, anything else as its JSON) through the `store`
target and binds it under `name` or the next free `r<n>`; it answers the
result's card. `describe(r)`, given a name, a handle or a card, answers that
card again from the manifest: name, size, lines, completion, taint and a
preview a tainted body withholds. The names live in the run's replay record,
so they survive steps, compaction and restart. An unknown name throws
`unknown_handle` with the live names.
`store(value, name, {sources})` names the results a value was made from; the
stored body inherits their taint. `store(value, name, {receipt: {source,
tasks, tree?, recipe?}})` stores a fold: the host checks that each task is a
reader child of this run over `source`, computes the fold receipt (the ranges
its children read, the ranges none read, the children that stopped short and
why, the summary tree, every occurrence whose taint the body inherits) and
writes it with the binding in the checkpoint's one transaction. The card
answers `receipt: {read, unread, partial, children}`.
`chunks(r, {tokens, max_bytes?})` cuts text by the executor's tokenizer: each
chunk grows line by line to about `tokens`, at most `max_bytes`; one call
tokenizes at most 8 MiB (`CHUNK_TOKEN_PAGE_BYTES`) and answers `next`.
`summarize(r, {effort?, group?, defer?})` is one verb-table row: one model
call over `r` and the `group` after it, made by a reader job of the run on its
route, never inside the step, and memoised by those results' occurrences and
the recipe. A made summary answers its card and `task`. `defer: true` answers
`{task, state}` to wait on with `tasks.wait`; otherwise the run parks until the
summary is made and the same call answers it after the resume. A withheld
member answers its withheld reply and nothing is summarized; a group too big
for half the model's window settles `group_exceeds_window`.
Two bundled helpers are SDK code over those verbs, not engine verbs, and live
in their own files: `readAll(r, {ask, by?, window?, until?, n_of?, effort?,
key?})` (`reader_forks.js`) reads a result with reader children (chunks of
half the child window, one `self.spawn` each, `tasks.wait`, findings deduped
by the ranges they cite, staged `summarize` groups) and stores the fold as
`rf_<key>` with its receipt. It runs in phases kept in `rf_<key>_state`: call
it again with the same arguments until `done`. `diff(a, b, {by?, from?,
name?})` (`diff.js`) states its algorithm: by lines, Myers' O(ND) inside
lockstep 4096-line windows, by bytes 64 KiB blocks; hunk text past 1 MiB is
stored as a result made from both sides. Every default and bound either
helper keeps is one named top-level const in its file.
Foreign guests have no `self` object. Their `propose.file(...)` and
`propose.claim(...)` produce typed proposal deltas, not committed writes.
Only workspace/output file paths are proposal targets; upload and skill files
remain read-only. Native globals (`process`, `require`, `fetch`, `std`, `os`)
are absent. No import loader can reintroduce them.

First-party code gets one async method per SDK verb-table row the host
serves, at the row's full path (`vault.recall(input)`, `tasks.create(input)`,
`self.focus.refresh(input)`, a bare `describe(input)`).
Bootstrap builds them from the hidden `self.verbs` imports and then deletes
`self.verbs`, so a row added to `scripts/sdk/agent-verbs.json` reaches the guest
with no component rebuild. The memory reads and writes the run answers itself
(`vault.search`, `vault.claims.put`, `vault.claims.supersede`,
`vault.edges.put`) are rows of the same table, so they arrive the same way. A
verb input is encoded once and the call sends that text. One holding a
non-finite number, boxed or not, is refused before the call
(`non_finite_verb_input`), since JSON would carry it as null; one JSON
cannot carry at all is `invalid_verb_input`. A refused call throws a stable
code, never prose, and so does the bridge's own argument check
(`invalid_host_argument`).

The interpreter has its own 24 MiB tracked heap and instruction-interrupt cap.
Wasmtime adds bounded fuel, linear memory, stack, wall time and host-call counts.
The host refuses any first-party proposal rather than silently committing it.

## Hook guest

`quickjs-hook.wasm` runs a hook body (`hook_guest.c`, `hook_bootstrap.js`), not
a code-mode step. Its world imports only `scoped-read`, `ai-verdict` and
`emit-outcome` and exports `run-hook(source, input-json)`. None of the code-mode SDK is linked:
no files, credentials, verbs, asks, clock or random, and no WASI.

The body is plain JS run as an async function body. `input` is the parsed,
frozen input JSON. `await oneiron.read(request)` sends the request as JSON
through `scoped-read` and resolves to the parsed answer; a host refusal
rejects with its code. `await ai.verdict(request)` sends an `ai.verdict`
input through `ai-verdict` the same way. The host answers it only for a fact
hook that declares `render_class: generative`; any other body's call is
refused. The body returns its one outcome or calls
`oneiron.emit(outcome)` once. Returning nothing without an emit is
`{"kind":"nothing"}`. A second outcome is refused. `Date` reads `input.now`
(Unix ms, UTC), and `Math.random` throws `hook_has_no_random`. The guest
keeps the code-mode 24 MiB JS heap, 256 KiB JS stack and interrupt cap.

The host is `oneiron::runtime_hooks::sandbox::HookSandbox` (feature
`code-sandbox-wasmtime`). `HookSandbox::from_component(bytes, blake3_pin)`
checks the pin, refuses any import outside the three, checks the `run-hook`
export and runs a real-JS readiness probe. `hook_component_bytes()` returns
the checked-in artifact and its BLAKE3 pin, `HOOK_COMPONENT_BLAKE3`, which
must be replaced along with the artifact. Each `run_hook` gets a fresh Store
under the code-mode fuel, memory, stack, host-call and message limits. The
deadline is the hook's `budget_ms`, and it covers start-up and reads. Every
read and verdict debits the host-call budget. A read request may carry 4 KiB,
a verdict request 64 KiB, and an answer 256 KiB.

## Production MCP binding

Build `oneiron-server` with `--features code-sandbox-wasmtime`. Load the reviewed
artifact with `QuickJsRuntimeFactory::from_component`, then construct
`McpQuickJsProvider` with the actual `LlmBackend`, issued `BudgetLease`, stable
`EngineExecutorConfig`, and verified factory. Bind it before creating routes:

```text
SyncServer::new(vault, server_config)?.with_mcp_quickjs_provider(provider)
```

The host belongs to that server/vault, not the process. No backend or spend lease
is invented by startup. Servers without this explicit verified binding keep
`execute_code` unavailable and omit it from listings. Bound servers advertise
it on both MCP endpoints. Actor resolution, scope admission, gate dispatch,
checkpoint persistence, and result envelopes use the existing engine paths.
Narrow world/facet credentials remain refused, rather than gaining vault-wide
execution through the new door.

Reuse `run_ref` and `task` to resume a yielded run. Completed re-entry returns
the persisted result without a second effect. A changed task, interpreter pin,
or actor identity cannot reuse the existing replay identity. Concurrent calls
to the same run fail with `code_run_busy`; disconnect does not release the
worker's single-flight guard. A durable human wait remains parked until the
engine supplies a settlement door; this change does not claim to settle waits.

## Required artifact acceptance

Point tests at the built directory (or use the checked-in artifacts directory):

```text
ONEIRON_QUICKJS_ARTIFACT_DIR=/absolute/path/to/target/code-run-quickjs cargo nextest run -p oneiron --features code-sandbox-wasmtime -E 'test(quickjs_)'
ONEIRON_QUICKJS_ARTIFACT_DIR=/absolute/path/to/target/code-run-quickjs cargo nextest run -p oneiron-server --features code-sandbox-wasmtime -E 'test(quickjs_)'
```

Missing artifacts fail the enabled acceptance tests. They are not silently
skipped and WAT is never substituted. The server test uses actual HTTP MCP
calls, the production provider, real JS, a durable claim write, a resumed run,
and a terminal retry. Core fixtures cover typed traps, deterministic clock/RNG,
fresh globals, escape refusal, resource limits and foreign proposal outputs.
