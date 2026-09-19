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

- `quickjs-first-party.wasm`: all 13 typed imports;
- `quickjs-foreign.wasm`: only the four non-write imports;
- `manifest.json`: source, WIT, toolchain and artifact pins.

The foreign WIT file is a generated import projection of the same world, not
another protocol. `run-step` and every record/variant stay byte-identical.
Do not install the first-party artifact in a foreign VM. The foreign linker
refuses it before guest code runs.

The checked-in `components/code-run-quickjs/artifacts/` contains both component
files, the emitted manifest and upstream LICENSE. A second controlled build in
a different output directory produced byte-identical component SHA-256 values.
For each source change, rebuild and replace all four files together.
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
completed step. `writeOutput('/mnt/outputs/name', bytes)` returns an output file.
Foreign guests have no `self` object. Their `propose.file(...)` and
`propose.claim(...)` produce typed proposal deltas, not committed writes.
Only workspace/output file paths are proposal targets; upload and skill files
remain read-only. Native globals (`process`, `require`, `fetch`, `std`, `os`)
are absent. No import loader can reintroduce them.

The interpreter has its own 24 MiB tracked heap and instruction-interrupt cap.
Wasmtime adds bounded fuel, linear memory, stack, wall time and host-call counts.
The host refuses any first-party proposal rather than silently committing it.

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
