# oneiron-uniffi — the SDK verb table, UniFFI-bound

> **Status: executable binding.** The `Oneiron` handle holds the shared
> `oneiron_remote::OneironClient`, the same Rust client the `oneiron` npm and
> PyPI packages hold. `open` binds an embedded, in-process vault (no server,
> no Docker, no API key: the on-device Swift path); `connect` binds a remote
> `oneiron-server`. Every facade row of `scripts/sdk/agent-verbs.json` is one
> exported method that calls the client's typed method for that row on
> either backend. No Swift or Kotlin package is published yet, and no
> XCFramework is produced.

## What this is

- One workspace crate holding proc-macro UniFFI records, enums, the error,
  the `Oneiron` object and its scaffolding. There is **no `.udl` file** and
  **no `build.rs`**; proc-macro metadata plus the version-locked local
  bindgen binary (`uniffi-bindgen`, behind the `bindgen-cli` feature) are the
  only generation path.
- **One client, no second transport.** The crate depends on `oneiron-remote`
  and nothing else that talks to a network. Remote calls go through that
  client's one HTTP stack, signed with the credential's connection key;
  embedded calls go through its one dispatcher, writer lease and owner actor.
- **Generated, not hand-bound.** `scripts/sdk/generate.py` writes
  `src/facade_generated.rs` from the verb table: one `export_facade!` arm per
  facade row (host-door rows included). Each arm lowers its foreign
  arguments into the row's engine input, calls the row's typed
  `OneironClient` method, and lifts the engine output back through the
  type-keyed codecs in `src/codec.rs`. The macro emits
  `EXPORTED_UNIFFI_VERBS` and `EXPORTED_UNIFFI_RUST_NAMES` from the same
  invocation, so the ledgers name exactly the exported methods.

## Constructors and handle methods

| Rust | generated Swift | what it does |
|---|---|---|
| `open(path: Option<String>, options: Option<OpenOptions>)` | `Oneiron.open(path:options:)` | embedded vault; an omitted path is `~/.oneiron/default`; `OpenOptions.dimensions` is the embedding width. Installs the engine panic hook first |
| `connect(url: String, key: String)` | `Oneiron.connect(url:key:)` | remote server; the key is the credential `pair` returned, passed verbatim and never parsed here |
| `pair(link: String) -> Paired` | `pair(link:)` | redeems a one-use pairing link for `{url, credential}` |
| `as_actor(actor_key: String)` | `client.asActor(actorKey:)` | a NEW handle for another actor; a connected handle refuses `FORBIDDEN` |
| `in_room_turn(room_ref: String)` | `client.inRoomTurn(roomRef:)` | a NEW handle whose every verb runs as a turn in that room |
| `last_receipt_ref() -> Option<String>` | `client.lastReceiptRef()` | the `call:<32hex>` receipt the last remote reply stated; `nil` when embedded |

Errors cross as one `OneironError.Failure(code, message, suggestions,
attempted, replacement, schemaRef)`: the engine's `MEMORY_CODE_*` string
verbatim, ordered suggestions, and the wrong-root correction when there is
one.

## Which verbs cross typed, and which cross `WireJson`

A row's input and output cross as UniFFI records wherever the crate has one;
everything else crosses as the `WireJson { canonical_json }` leaf. A
`WireJson` input is parsed into the row's engine input type on the Rust side,
so the engine type's own shape validates it, and the typed engine output is
written back as one JSON value. That is still one typed method per verb with a
JSON body: there is no generic `call(name, json)`.

- **Typed in and out (24):** `vault.witness`, `vault.claims.upsert`,
  `vault.recall`, `vault.receipts`, `vault.rooms.speak`, `vault.commit`,
  `vault.remember`, `vault.claims.retract`, `vault.forget`,
  `vault.claims.list`, `vault.claims.history`, `vault.delete`,
  `vault.writes.pending`, `vault.hydrate`, `vault.get`, `vault.search.bm25`,
  `vault.neighbors`, `vault.structural.put`, `vault.habits.checkin`,
  `vault.claims.admit`, `vault.artifacts.put`, `vault.artifacts.append`,
  `vault.artifacts.read`, `connector.outbound.schedule`.
- **Typed arguments, `WireJson` result (3):** `cancel(taskRef:)`,
  `describe(taskRef:)`, `vaultExport(format:)`.
- **`WireJson` input, typed result (2):** `vault.notes.create`,
  `vault.notes.from_entity` (both return `EntityRefReceipt`).
- **`WireJson` in and out:** every other facade row (124 on this head). The
  generated file is the authoritative list; each method is named for its row
  (`vault.kv.get` is `vaultKvGet(input:)`).
- **Definition-only (3):** `vault.consolidation.enqueue`,
  `vault.consolidation.status`, `vault.claims.seed` keep their typed
  signatures and fail closed with `INVALID_STATE` until the table gives them
  callable rows.

`vault.recall` takes `effort` (`light` … `max`, or `call`: light effort under
a hard deadline) and `deadlineMs`. Embedded, `high`/`xhigh`/`max` return the
engine's `LEASE_REQUIRED`: this client mints no lease. `MemoryPack` carries
items with provenance, `reactions` and `citedMessages`, scope honesty with
`censusCapped`, retrieval accounting, `packVersion` (always
`HEAD_MEMORY_PACK_SCHEMA_VERSION`) and the read's `narrowing` receipt. The
read verbs return `{value, narrowing}`. Blob content crosses as bytes; an
omitted write time is stamped with the current Unix second at the call.

Host-door rows are exported like every other row. An embedded handle answers
them with the row's own embedded `call`; the ones only a server's state can
answer (its model seats, the owner proof) refuse there, typed. Running the
full server inside an app over `EmbeddedHost` is not wired yet.

## Toolchain pin

`uniffi = "0.29"` is pinned for the proc-macro runtime **and** the local
bindgen CLI feature, so generated output and scaffolding always come from one
release line. A move to a newer line changes the generated Swift surface.

## Generating bindings

```sh
bash crates/oneiron-uniffi/swift/run-stub-compile.sh
```

The script builds the library, runs the crate-local bindgen binary in library
mode into `swift/.generated/`, and runs `swift build` on the compile stub in
`swift/Sources/OneironUniFFIStub/main.swift`. The stub is hand-maintained and
lags the generated surface; it is a compile probe, not a consumer.

A surface change edits the verb table and reruns
`python3 scripts/sdk/generate.py`; a new typed record adds its codec in
`src/codec.rs` and its engine type to the emitter's `UNIFFI_INPUTS` or
`UNIFFI_RESULTS` table.
