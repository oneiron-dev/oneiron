//! C ABI for on-device iOS and macOS access to the Oneiron vault.
//!
//! Variable-size outputs are allocated by Rust and returned through
//! `OneironBuffer` or typed array structs. Callers must release those values
//! with the paired `oneiron_*_free` function from this crate. Never pass these
//! pointers to the platform allocator, and never free the same value twice.
//!
//! Sync entry points are intentionally absent here and on the N-API surface
//! while shared multi-vault sync is disabled.
//! The core read/write N-API vault surface is mirrored by this C ABI.
//!
//! With the `engine` feature, `oneiron_engine_start` runs the full server
//! `oneiron serve` runs inside the app's process (OF-237);
//! `oneiron_engine_vault` hands the same open vault to the storage functions
//! above, beside the plain `oneiron_vault_open`.
//!
//! # Safety
//!
//! Every entry point is an `unsafe extern "C" fn` with a `# Safety` section:
//! its arguments are raw pointers only the caller can vouch for, so a Rust
//! caller writes `unsafe` and takes on the same contract a C or Swift caller
//! takes on from the header.
//!
//! ```
//! let mut vault = std::ptr::null_mut();
//! // SAFETY: a null path is refused before any read, and `vault` is writable.
//! let status = unsafe {
//!     oneiron_ffi::oneiron_vault_open(std::ptr::null(), 0, 0, std::ptr::null(), 0, &mut vault)
//! };
//! assert_eq!(status, oneiron_ffi::OneironStatus::NullArg);
//! ```
//!
//! Safe Rust cannot make the same call:
//!
//! ```compile_fail,E0133
//! let mut vault = std::ptr::null_mut();
//! oneiron_ffi::oneiron_vault_open(std::ptr::null(), 0, 0, std::ptr::null(), 0, &mut vault);
//! ```
//!
//! The owning descriptors move rather than copy, so one value reaches its
//! free function once. Borrowed inputs stay `Copy`:
//!
//! ```
//! fn copy<T: Copy>() {}
//! copy::<oneiron_ffi::OneironByteSlice>();
//! copy::<oneiron_ffi::OneironEntityInput>();
//! ```
//!
//! ```compile_fail,E0277
//! # fn copy<T: Copy>() {}
//! copy::<oneiron_ffi::OneironBuffer>();
//! ```
//!
//! ```compile_fail,E0277
//! # fn copy<T: Copy>() {}
//! copy::<oneiron_ffi::OneironEdgeInfoArray>();
//! ```
//!
//! ```compile_fail,E0277
//! # fn copy<T: Copy>() {}
//! copy::<oneiron_ffi::OneironScoredEntityArray>();
//! ```
//!
//! ```compile_fail,E0277
//! # fn copy<T: Copy>() {}
//! copy::<oneiron_ffi::OneironSubtreeEntryArray>();
//! ```

mod alloc;
#[cfg(feature = "engine")]
mod engine;
mod entity;
mod guard;
mod parse;
mod query;
mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "engine")]
pub use self::engine::{
    OneironAppHost, OneironEngine, OneironReply, OneironSecretSink, oneiron_engine_free,
    oneiron_engine_reply_free, oneiron_engine_request, oneiron_engine_start, oneiron_engine_stop,
    oneiron_engine_vault, oneiron_engine_wake, oneiron_secret_sink_write,
};
pub use self::entity::{
    oneiron_buffer_free, oneiron_edge_info_array_free, oneiron_scored_entity_array_free,
    oneiron_subtree_entry_array_free, oneiron_vault_batch_put_entities,
    oneiron_vault_delete_entity, oneiron_vault_entity_exists, oneiron_vault_free,
    oneiron_vault_get_entity, oneiron_vault_health_json, oneiron_vault_open,
    oneiron_vault_put_entity,
};
pub use self::query::{
    oneiron_vault_ancestors, oneiron_vault_context_pack, oneiron_vault_edges_in,
    oneiron_vault_edges_out, oneiron_vault_entities_by_type, oneiron_vault_get_entity_type,
    oneiron_vault_put_edge, oneiron_vault_put_vector, oneiron_vault_search_text,
    oneiron_vault_search_vector, oneiron_vault_sources, oneiron_vault_subtree,
    oneiron_vault_targets, oneiron_vault_would_create_cycle,
};
pub use self::types::{
    OneironBuffer, OneironByteSlice, OneironEdgeInfo, OneironEdgeInfoArray, OneironEntityInput,
    OneironScoredEntity, OneironScoredEntityArray, OneironStatus, OneironSubtreeEntry,
    OneironSubtreeEntryArray, OneironVault,
};

// The flat lib.rs module used to provide these names to the sibling test
// module through `use super::*`: the private limit constants plus the crate
// and std imports the tests name bare. After the directory split the seam
// re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::types::{ENTITY_ID_LEN, MAX_FFI_QUERY_BYTES, MAX_FFI_SEARCH_LIMIT};
#[cfg(test)]
use oneiron::EdgeKind;
#[cfg(test)]
use std::{ptr, slice};
