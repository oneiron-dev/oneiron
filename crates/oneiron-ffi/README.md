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
