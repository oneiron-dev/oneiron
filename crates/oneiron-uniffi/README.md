# oneiron-uniffi — the SDK verb table, UniFFI-bound

> **Status: executable binding.** The `Oneiron` handle holds the shared
> `oneiron_remote::OneironClient`, the same Rust client the `oneiron` npm and
> PyPI packages hold. `open` binds an embedded, in-process vault (no server,
> no Docker, no API key: the on-device Swift path); `connect` binds a remote
> `oneiron-server`. Every facade row of `scripts/sdk/agent-verbs.json` is one
> exported method that calls the client's typed method for that row on
> either backend. `EmbeddedEngine` (the `engine` feature) runs the full
> server inside the app's process over the same kind of handle. No Swift or Kotlin package is
> published yet, and no XCFramework is produced.

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
  The embedded engine's `oneiron-server` edge serves the API over
  in-process streams and binds no API socket.
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
| `retry(pending: WireJson, verb: String, input: WireJson) -> WireJson` | `client.retry(pending:verb:input:)` | resends a call a verb hook stopped on an ask under its invocation: `pending` is the `PENDING_ASK` failure's `pending` payload, `input` the same input; answers the verb's wire JSON |
| `lens_frame_event(card_id: String, request: WireJson) -> WireJson` | `client.lensFrameEvent(cardId:request:)` | sends one `{event, idempotencyKey}` on a lens card the connected server rendered; answers `{"$state"}` or `{outcome, readReceipt}` |
| `close_lens_frame(card_id: String) -> WireJson` | `client.closeLensFrame(cardId:)` | closes that card and frees its frame; answers `{closed}` |

The two lens-card methods are routes outside the facade (OF-181), not verbs. A
card's frame lives only on the server that rendered it (`vault.lenses.default`),
so an embedded handle fails `BAD_REQUEST`. Their JSON keeps the wire's camelCase.

Errors cross as one `OneironError.Failure(code, message, suggestions,
attempted, replacement, schemaRef, pending)`: the engine's `MEMORY_CODE_*`
string verbatim, ordered suggestions, the wrong-root correction when there is
one, and on a `PENDING_ASK` the whole refusal as `pending`, for `retry`.

## Which verbs cross typed, and which cross `WireJson`

Every facade row crosses typed. A row whose engine type has a hand-written
record in `src/dto.rs` crosses through it; every other row crosses through the
records and enums `scripts/sdk/generate.py` writes into
`src/facade_types_generated.rs` from the facade type inventory
(`scripts/sdk/facade_types.py`, the one walker the TypeScript and Python
declarations also read; `scripts/sdk/uniffi_types.py` projects it). That is
one `uniffi::Record` or `uniffi::Enum` per engine struct or enum the rows
reach, each deriving serde with the engine type's own wire shape: the same
keys, the same enum tagging, the same optional fields. A row converts at its
boundary through that shape, so the engine type's own serde validates every
input. An input with no fields is no argument (`vaultRoomsList()`). There is
no generic `call(name, json)`.

- **Hand-written records in and out (27):** `vault.witness`,
  `vault.claims.upsert`, `vault.recall`, `vault.receipts`,
  `vault.rooms.speak`, `vault.commit`, `vault.remember`,
  `vault.claims.retract`, `vault.forget`, `vault.claims.list`,
  `vault.claims.history`, `vault.delete`, `vault.writes.pending`,
  `vault.hydrate`, `vault.get`, `vault.search.bm25`, `vault.neighbors`,
  `vault.structural.put`, `vault.habits.checkin`, `vault.claims.admit`,
  `vault.artifacts.put`, `vault.artifacts.append`, `vault.artifacts.read`,
  `vault.consolidation.enqueue`, `vault.consolidation.status`,
  `vault.claims.seed`, `connector.outbound.schedule`.
- **Typed arguments, generated result (3):** `cancel(taskRef:)`,
  `describe(taskRef:)`, `vaultExport(format:)`.
- **Generated input, hand-written result (2):** `vault.notes.create`,
  `vault.notes.from_entity` (both return `EntityRefReceipt`).
- **Generated in and out:** every other facade row, host doors included (254
  of the 286 facade rows on this table). The generated files are the
  authoritative list; each method is named for its row (`vault.kv.get` is
  `vaultKvGet(input:)` over the `KeyValueAddress` record).
- **`WireJson`** stays only where UniFFI cannot say the shape, as a field
  inside its record and never as the whole argument: each `serde_json::Value`
  (a claim's value, a task spec, an entity body, `ai.*` params and the
  others `generate.py` lists), each tuple (`DeckNodeView.placeholder`,
  `GeometryProps.extent` and `.offset`, `TaskStatusView.asks`, `XlsxArea.first`
  and `.last`), and the one type on a by-value cycle, `ProjectWriteProof` at
  `ProjectRecord.write_proof` (its anchor holds an optional proof, and a record
  cannot hold itself by value). A tree that reaches itself only through a
  list is an ordinary record: `LensNode` (`GeneratedLens.root`) and
  `RunTreeNode` (`RunTree.roots`) cross typed. A row whose type the inventory
  could not read would cross as `WireJson` whole on that side; on this table
  no row does. The generated file's header carries the census.
- Where a generated type would take a hand-written record's name it is
  prefixed `Wire` (`WireClaimView`, `WireEntityView`, ...): the same engine
  type, carried at its wire widths.
- **Definition-only:** none. Every exported row is callable; the generator
  refuses a definition row a UniFFI signature.

`vault.recall` takes `effort` (`light` … `max`, or `call`: light effort under
a hard deadline) and `deadlineMs`. Embedded, `high`/`xhigh`/`max` return the
engine's `LEASE_REQUIRED`: this client mints no lease. `MemoryPack` carries
items with provenance, `reactions` and `citedMessages` (each with its typed
`record` ref), scope honesty with
`censusCapped`, retrieval accounting, `packVersion` (always
`HEAD_MEMORY_PACK_SCHEMA_VERSION`) and the read's `narrowing` receipt. The
read verbs return `{value, narrowing}`. Blob content crosses as bytes; an
omitted write time is stamped with the current Unix second at the call.

Host-door rows are exported like every other row. An embedded handle answers
them with the row's own embedded `call`; the ones only a server's state can
answer (its model seats, the owner proof) refuse there, typed, on a handle
from `EmbeddedEngine.localClient()` too. A handle from
`EmbeddedEngine.client(key:)` answers them as any server does: every verb
crosses the engine's own Router in process, under the caller's credential.

## Embedded engine

`EmbeddedEngine` runs the full server `oneiron serve` runs inside the app's
own process (`oneiron_server::embedded::BlockingEngine`), next to `open`,
which stays a plain vault with no server. It and `AppHostCallbacks` exist
only when the library is built with `--features engine`
(`cargo build -p oneiron-uniffi --features engine`), and bindgen run over
that build; the default build, the one `run-stub-compile.sh` makes, has
neither.

| Rust | generated Swift | what it does |
|---|---|---|
| `start(path, options, config_file, host, limits)` | `EmbeddedEngine.start(path:options:configFile:host:limits:)` | opens the vault at `path` the way `oneiron serve --config <config_file>` does (that config for this path, with `options.dimensions` when given), serves it, and returns once `host.ready()` has run. Refuses a relay host's config. Absent `limits` fields are unbounded |
| `client(key) -> Oneiron` | `engine.client(key:)` | a NEW handle the engine's server serves in process under `key`, the caller's own credential (the one `pair` returned, or the host secret as a bare bearer): every verb, `retry` and lens-frame call POSTs the facade route through the server's Router with that credential, a fresh holder proof, the room turn and the invocation, as a connected handle does over the network, host doors included. `asActor` refuses on it, as on a connected handle. It keeps the engine alive |
| `local_client() -> Oneiron` | `engine.localClient()` | a NEW handle attached to the engine's own vault, bound to the embedded owner actor, never a second open; its verbs answer through the vault, not the server. Ask again for each handle. Every handle keeps the engine alive |
| `request(EngineRequest) -> EngineReply` | `engine.request(request:)` | one buffered HTTP/1.1 exchange over a fresh in-process stream; headers pass through (bring your own auth); a 4xx/5xx is a reply. A reply body over 64 MiB, `/ws` and other upgrades are refused |
| `open_connection() -> EngineConnection` | `engine.openConnection()` | a connection the app holds: one in-process stream the server serves as a socket's connection, HTTP/1.1 with upgrades. `send(bytes:)` writes the request (a `GET /ws` with its upgrade headers holds `/ws`; after the `101`, the upgraded protocol's frames), `receive()` returns the next bytes the server wrote (at most 64 KiB; empty once it ended), `close()` ends the app's side and returns a blocked `receive`. Refused while stopped; a stop drains it, so after `wake` open another. It keeps the engine alive |
| `wake()` | `engine.wake()` | the app's timer fired: run what is due; a stopped engine serves again first, over the same vault |
| `stop()` | `engine.stop()` | the app backgrounds: drain, stop every worker, keep the vault open |
| `close()` | `engine.close()` | the ordered stop, then the runtime goes; later calls refuse |

The app implements `AppHostCallbacks`: `keychain(name)` returns the secret's
bytes or `nil` (the server then falls back as it does on a desktop),
`scheduleWake(atUnixMs:)` arms or clears (`nil`) the app's timer, and
`ready()` reports the server up. The engine calls them on threads of its
own; a call back into the engine from one is refused. The engine owns a
multi-thread Tokio runtime and blocks the calling thread, so call it from
app threads, and call `close()` from one before the app lets it go.

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

A surface change edits the verb table or the engine types and reruns
`python3 scripts/sdk/generate.py`, which regenerates both files. A
hand-written record (one with foreign widths or call-time stamping) adds its
codec in `src/codec.rs` and its engine type to the emitter's `UNIFFI_INPUTS`
or `UNIFFI_RESULTS` table.
