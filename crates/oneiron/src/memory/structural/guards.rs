//! Create-only guards for the structural write door (ONE-1889).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

use super::kind_string_for_type;
/// ONE-1889: the broad structural door is CREATE-ONLY. Any stored row at `id`
/// refuses the put, whatever its kind and whatever kind is incoming — the
/// guard reads the STORED type, never the caller's, so reusing a live id with
/// a different kind cannot clobber its body.
///
/// Call this inside the would-be put's own write transaction, after the
/// hard-delete marker check and before any staging, so a refusal costs no
/// entity bytes, edges, text postings, temporal rows, or short ids, and a
/// concurrent create resolves to exactly one winner and one refusal.
pub(super) fn ensure_structural_create_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<()> {
    let Some(stored_type) = vault.get_entity_type_in_txn(txn, id)? else {
        return Ok(());
    };
    Err(structural_overwrite_refusal(stored_type))
}
/// The one stable refusal [`ensure_structural_create_in_txn`] returns. Keyed
/// solely on the STORED kind, so same-kind and cross-kind retries at the same
/// id are indistinguishable: the caller learns which kind owns the id and
/// which door to use, never anything about the stored body.
fn structural_overwrite_refusal(stored_type: u8) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{} entities cannot be overwritten through the structural door",
            kind_string_for_type(stored_type),
        ),
        &[
            "put_structural is create-only; this id already holds a stored entity.",
            "Create a new entity, or use the stored kind's typed mutation verb.",
        ],
    )
}
