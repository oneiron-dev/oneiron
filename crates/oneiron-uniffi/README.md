# oneiron-uniffi — WIRE head contract, UniFFI definition surface

> **Status: definition artifact + compile proof only.** This crate declares
> the UniFFI interface for the WIRE head contract and proves that the
> generated Swift API compiles. It is **not** a shipped SDK, **not** runtime
> product wiring, and nothing here opens storage, performs network I/O,
> mints a lease, or schedules an effect. Every constructor and verb body
> fails closed with a typed `INVALID_STATE` error until the first runtime
> consumer replaces the bodies with core facade calls.

## What this is

- One self-contained workspace crate (`crates/oneiron-uniffi`) holding
  proc-macro UniFFI records, enums, errors, the `Oneiron` object, and
  scaffolding for the WIRE head contract. There is **no `.udl` file** and
  **no `build.rs`**; proc-macro metadata plus the version-locked local
  bindgen binary are the only generation path.
- A pinned 27-verb ledger (`PINNED_HEAD_CONTRACT_VERBS`) maintained
  independently of the proc-macro declarations, so coverage and naming
  drift are mechanically checked instead of reviewed by eye.
- A standalone Swift package (`swift/`) whose never-run compile consumer
  references the complete generated interface: both constructors, actor
  rebinding, every pinned verb, every DTO's full memberwise initializer,
  and the three-field error shape.
- A crate-local `uniffi-bindgen` binary (behind the `bindgen-cli` feature)
  so the generator can never drift from the compiled library.

## What this is not

- Not wired into any product. No Swift/Kotlin package is published, no
  XCFramework is produced, and no downstream repository imports this.
- Not a runtime quickstart. Constructors return the same `Oneiron` handle
  type, but fail closed: the definition binds no actor, stores no state,
  and answers every call with `INVALID_STATE`.
- Not a change to the existing raw C ABI. `crates/oneiron-ffi/` and the
  root `Package.swift` are untouched and remain the community fallback.
- Not a second transport. There is one Rust facade and N bindings; the
  remote mode's runtime wiring must consume the single Rust remote client
  from the P1 arm when a consumer lands. This lane adds no HTTP/WS client,
  no subscription verb (streaming belongs to the BRIDGE transport), and no
  foreign callback interface.

## Toolchain pin

`uniffi = "0.29"` is pinned for the proc-macro runtime **and** the local
bindgen CLI feature, so generated output and scaffolding always come from
one release line. Crates resolve `0.29` to the newest `0.29.x` patch.

Latest stable verified at authoring: **`uniffi 0.32.0`** (crates.io,
2026-08-10). Staying on the pinned `0.29` line is deliberate; any move to a
newer major-minor line is a contract amendment that re-verifies the ledger
tests, the generated Swift surface, and the compile stub together — it is
not ambient dependency drift.

## Head contract

Two constructors return the same `Oneiron` handle type:

| Rust definition | generated Swift | rule |
|---|---|---|
| `open(path: Option<String>, options: Option<OpenOptions>)` | `Oneiron.open(path:options:)` | embedded mode; an omitted path resolves to the engine default directory at runtime |
| `connect(url: String, key: String)` | `Oneiron.connect(url:key:)` | remote mode; the key is an opaque minted slip, never parsed by the foreign layer |
| `as_actor(actor_key: String)` | `client.asActor(actorKey:)` | narrower actor scope on the same handle type; not a verb |

The generated error contract is `OneironError.Failure(code, message, suggestions)`: one variant, three fields, and `suggestions` is never
dropped or flattened into `message`. `recall` returns the versioned
`MemoryPack`; `HEAD_MEMORY_PACK_SCHEMA_VERSION` is sourced from
`oneiron::MEMORY_PACK_VERSION` so the declared schema can never go stale.

The 27 pinned verbs, in canonical SDK spelling:

`witness`, `recall`, `receipts`, `commit`, `claimUpsert`, `remember`,
`claimRetract`, `forget`, `claimList`, `claimHistory`, `safeDelete`,
`pendingWrites`, `hydrate`, `getEntity`, `queryBm25`, `neighbors`,
`putStructural`, `putHabitCheckin`, `putCompanionRecord`,
`admitImportedClaim`, `putBlobArtifact`, `appendBlobVersion`,
`readBlobVersion`, `enqueueConsolidation`, `dreamerJobStatus`,
`seedClaims`, `scheduleOutbound`.

`dreamerJobStatus` keeps the ledger spelling; the runtime arm maps it to
the core attempt-status accessor, as the direct-link binding already does.
`scheduleOutbound` schedules only — it never becomes a send transport.
Blob content crosses as bytes (`Data` in Swift); `appendBlobVersion` takes
optional `i64` Unix-second timestamps, and `readBlobVersion` is
version-addressed with `version: u64`.

## Generating bindings and running the compile proof

```sh
bash crates/oneiron-uniffi/swift/run-stub-compile.sh
```

The script builds the Rust library (cdylib carries the metadata, staticlib
links the Swift target), runs the crate-local bindgen binary in library
mode into `swift/.generated/`, lays out the generated C module and Swift
target, and runs `swift build` against the compiled static archive. The
generated files are build outputs and are never committed; the executable
is never run and no XCFramework is produced.

Rust-side checks:

```sh
cargo fmt --check --package oneiron-uniffi
cargo clippy -p oneiron-uniffi --all-targets --all-features -- -D warnings
cargo test -p oneiron-uniffi --all-features
```

CI runs all of the above plus a `.udl` census and a forbidden-path diff in
`.github/workflows/uniffi-stub.yml`.

## First-consumer trigger

The first runtime consumer — an app binding that needs the generated Swift
or Kotlin surface against a live vault — replaces the definition-only
bodies with actor-scoped core facade calls. It preserves the pinned verbs,
DTOs, error shape, and the coverage tests exactly; any desired surface
change is a head-contract amendment that moves the pinned list, the macro
invocation, the Rust-name drift guard, and the Swift compile probe
together. Populating live `pack_version` values and the live Swift throw
path are first-consumer scope, explicitly not claimed by this compile-only
lane.
