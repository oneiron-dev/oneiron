//! Core half of `vault::entity_refs`: its store-layer items live in `oneiron_store::vault::entity_refs` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault::entity_refs::*;

use crate::Vault;
use crate::entity_id::EntityId;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

/// Resolves a facade entity ref — 32-hex id or `"<short_id>:<hash-hex>"`
/// short ref — to an [`EntityId`]. Short refs must resolve in the vault.
///
/// The short-ref grammar comes from [`crate::entity_id::parse_short_ref_syntax`],
/// which is syntax only: a prefix no registry declares still PARSES here and
/// fails below with "does not resolve". That split is what lets a retired
/// prefix resolve through its alias row while an invented one does not.
pub fn resolve_entity_ref(vault: &Vault, reference: &str) -> MemoryResult<EntityId> {
    let reference = reference.trim();
    if reference.len() == 32 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return EntityId::from_hex(reference)
            .map_err(|_| MemoryError::bad_request(format!("invalid entity id {reference:?}")));
    }
    if let Ok((short_id, content_hash)) = crate::entity_id::parse_short_ref_syntax(reference) {
        return match vault.hydrate_short_id(short_id, content_hash)? {
            Some(entry) => Ok(entry.id),
            None => Err(MemoryError::not_found(format!(
                "short ref {reference:?} does not resolve"
            ))),
        };
    }
    Err(MemoryError::bad_request_with(
        format!("entity ref {reference:?} is neither a 32-hex id nor a short ref"),
        &["Pass a 32-character hex entity id or a short ref like \"ms1:a3\"."],
    ))
}
