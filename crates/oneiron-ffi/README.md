# Oneiron C ABI (`oneiron-ffi`)

C ABI for on-device iOS and macOS vault access. The header is generated from
`src/lib` via `cbindgen.toml` into `include/oneiron_ffi.h`. Variable-size
outputs are Rust-owned; release them with the paired `oneiron_*_free`
function, never the platform allocator, and never twice.

## Embedding model (census L9-28)

Every vector a vault stores names the model that computed it, so a host names
that model when it opens the vault: `oneiron_vault_open_with_embedding_model`
and `oneiron_vault_open_with_host_root_and_embedding_model` take its UTF-8 id,
`org/name@revision` (a malformed one is `InvalidArg`). `oneiron_vault_open` and
`oneiron_vault_open_with_host_root` name none, and every vector put on such a
handle is `EngineError` ("embedding model is required before writing
vectors"). The vault records the first model an open names; a later open
naming another is `EngineError`. Swift: `Vault.open(..., embeddingModel:)`.
N-API: a trailing optional `embeddingModel` on `new NapiVault(...)` and
`NapiVault.openWithHostRoot(...)`.

## Native limit questions (FIX 75)

`oneiron_vault_native_limit_questions` reads the latest engine-limit questions
a raw-opened vault asked: `out_available` is 1 on a carrying handle (0 on a
bound or engine-shared handle, which carry none), `out_json` the exact UTF-8
JSON array (`[]` when no row has crossed). Each element is exactly
`{"row", "bound", "measured"}` with full `u64` digits. Swift:
`Vault.nativeLimitQuestions()`. The read does not clear. Whole FIX 75 stays
PART for other language wrappers, queueing, memory floors, allocation and
runtime.
