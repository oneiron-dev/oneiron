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

mod alloc;
mod entity;
mod guard;
mod parse;
mod query;
mod types;

#[cfg(test)]
mod tests;

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
