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
- A standalone Swift package (`swift/`) whose never-run compile consumer
  references the complete generated interface: both constructors, actor
  rebinding, every facade verb, every DTO's full memberwise initializer,
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

The `0.29` line is pinned on purpose, although newer lines exist. A move to a
newer line changes the generated Swift surface, so the Swift compile stub moves
with it.

## Head contract

Two constructors return the same `Oneiron` handle type:

| Rust definition | generated Swift | rule |
|---|---|---|
| `open(path: Option<String>, options: Option<OpenOptions>)` | `Oneiron.open(path:options:)` | embedded mode; an omitted path resolves to the engine default directory at runtime |
| `connect(url: String, key: String)` | `Oneiron.connect(url:key:)` | remote mode; the key is an opaque minted slip, never parsed by the foreign layer |
| `as_actor(actor_key: String)` | `client.asActor(actorKey:)` | narrower actor scope on the same handle type; not a verb |

The generated error contract is `OneironError.Failure(code, message, suggestions)`: one variant, three fields, and `suggestions` is never
dropped or flattened into `message`. `vault.recall` returns the versioned
`MemoryPack`; `HEAD_MEMORY_PACK_SCHEMA_VERSION` is sourced from
`oneiron::MEMORY_PACK_VERSION` so the declared schema can never go stale.

The declared verbs, in canonical SDK spelling (the generated Swift method
folds the dots into camelCase: `vault.claims.upsert` is `vaultClaimsUpsert`):

`vault.witness`, `vault.recall`, `vault.receipts`, `vault.commit`,
`vault.claims.upsert`, `vault.remember`, `vault.claims.retract`,
`vault.forget`, `vault.claims.list`, `vault.claims.history`, `vault.delete`,
`vault.writes.pending`, `vault.hydrate`, `vault.get`, `vault.search.bm25`,
`vault.neighbors`, `vault.structural.put`, `vault.habits.checkin`,
`vault.claims.admit`, `vault.artifacts.put`, `vault.artifacts.append`,
`vault.artifacts.read`, `vault.consolidation.enqueue`,
`vault.consolidation.status`, `vault.claims.seed`,
`connector.outbound.schedule`.

`vault.consolidation.status` maps to the core attempt-status accessor, as
the direct-link binding already does.
`connector.outbound.schedule` schedules only — it never becomes a send transport.
The read verbs (`vault.get`, `vault.hydrate`, `vault.claims.list`,
`vault.claims.history`, `vault.search.bm25`, `vault.neighbors`) return
`{value, narrowing}`: their rows plus the read's mandatory `ReadReceipt`, the
same `narrowing` every other surface carries.
Blob content crosses as bytes (`Data` in Swift); `vault.artifacts.append`
takes optional `i64` Unix-second timestamps, and `vault.artifacts.read` is
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
bodies with actor-scoped core facade calls. The verb surface comes from
`scripts/sdk/agent-verbs.json`: `scripts/sdk/generate.py` writes
`src/facade_generated.rs` from its `uniffi` rows. A surface change edits the
manifest row and regenerates. The export macro emits the SDK-name and Rust-name
ledgers from the same invocation; the Swift compile stub
(`swift/Sources/OneironUniFFIStub/main.swift`) is updated by hand to reference
the new surface. Live `pack_version` values and the live Swift
throw path are left to that consumer; this crate does not provide them.
