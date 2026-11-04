//! Claim-policy traversal over the store's rebuildable projections.

use super::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::{EntityId, Error, Result};
use crate::store::Store;
pub(crate) use crate::store::claim_projection::{
    PENDING_PRODUCER, PREDICATE_NAME, remove_claim_projection_index, remove_claim_projection_index_in_rows, maintain_claim_projection_index, for_each_claim_id_for_predicate_in_txn, claim_ids_for_predicate_in_txn, claim_ids_for_predicate_page_in_txn, next_claim_world_in_txn, claim_ids_for_world_page_in_txn, claim_ids_for_predicate_bounded_in_txn, session_claim_producer,
};

/// Hands every claim id under a predicate live policy pins to `visit`,
/// classifying distinct stored predicates before any claim body is read. The
/// catalog and its posting lists co-commit with claim writes, and every
/// posting is read (FIX 8659).
pub(super) fn for_each_pinned_claim_id_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    mut visit: impl FnMut(EntityId) -> Result<()>,
) -> Result<()> {
    for predicate in PREDICATE_NAME.scan_keys(store, txn, &[])? {
        if policy.pins_predicate(&predicate) {
            for_each_claim_id_for_predicate_in_txn(store, txn, &predicate, &mut visit)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
