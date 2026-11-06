# Oneiron C ABI (`oneiron-ffi`)

C ABI for on-device iOS and macOS vault access. The header is generated from
`src/lib` via `cbindgen.toml` into `include/oneiron_ffi.h`. Variable-size
outputs are Rust-owned; release them with the paired `oneiron_*_free`
function, never the platform allocator, and never twice.

## Native limit questions (FIX 75)

`oneiron_vault_native_limit_questions` reads the latest engine-limit questions
a raw-opened vault asked: `out_available` is 1 on a carrying handle (0 on a
bound or engine-shared handle, which carry none), `out_json` the exact UTF-8
JSON array (`[]` when no row has crossed). Each element is exactly
`{"row", "bound", "measured"}` with full `u64` digits. Swift:
`Vault.nativeLimitQuestions()`. The read does not clear. Whole FIX 75 stays
PART for other language wrappers, queueing, memory floors, allocation and
runtime.

## Shared invitation acceptance and embedded bootstrap (FIX 12441 / 2051, partial)

With the `engine` feature, a `OneironRemote` is an actual connected native SDK
client. Its HTTPS accept/retry calls return an opaque `OneironSharedAcceptance`
that owns the original native acceptance. Request/reply JSON are reads of that
object, not a way to construct its provenance. `member_client` returns a new
native remote handle on the same home. The complete receipt remains readable
if a later member-client or bootstrap call fails.

`oneiron_engine_bootstrap_shared_env` uses that original acceptance and the
native `SharedEnvConfig` JSON (`path`, `vault_id`, `member`, `home_url`,
`credential_file`). A setup/task failure returns no outcome. An outcome keeps
the original native import result separate from its committed bit: read both.
`vault_path` returns only the actual held vault's path on success and returns
`EngineError` for any native import failure, including a failure after commit.
The non-consuming `outcome_error_json` reader exposes the complete original
native `MemoryError`, when present. Shared-call failures also leave that exact
native JSON in `oneiron_shared_last_error_json` on the calling thread, beside
the existing stable engine error channel. An empty JSON buffer means no native
`MemoryError`, not success; check the status/result as well.

`oneiron_engine_retain_shared_env` is a separate explicit caller act. It
upserts the entry in the same config file the engine originally served, for
its next start, without changing the running registry. Bootstrap never
implicitly persists the entry. Native config/credential handling and ordinary
admission remain in charge; these bindings add no owner authority.

Release every new handle with its paired free function exactly once and every
JSON/text buffer with `oneiron_buffer_free`. Calls block: use app threads,
never an engine-host callback. Swift supplies `RemoteClient`,
`SharedInvitationAcceptance`, `SharedBootstrapOutcome`, and Engine bootstrap/
retain methods. `SharedMemoryError.json` preserves the complete native error
bytes, including pending retry payloads. Other language bindings and the full
FIX 12441 / 2051 contract remain partial.
