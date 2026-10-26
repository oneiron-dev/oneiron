//! The verified closer of an exact lifecycle close (FIX 8655).

use crate::batch::VerifiedClaimTransition;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::store::Store;

/// Whether this write is the stored row's own exact close (only its
/// lifecycle and `valid_to` change, under a verified in-place transition) by
/// a closer its typed lifecycle door verified. Such a close admits nothing
/// new, so the birth source's Auto permits are not renewed for it against
/// the unchanged provenance: revoking one later cannot block the close. Any
/// other write, and a close with no verified closer, keeps every
/// source-trust check.
pub(super) fn exact_close_by_verified_closer(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    transition.is_some_and(|proof| proof.closer().is_some())
        && super::closes_stored_row_only(store, txn, id, body, transition)
}
