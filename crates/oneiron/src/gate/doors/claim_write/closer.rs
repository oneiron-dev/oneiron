//! The verified closer of an exact lifecycle close (FIX 8655).

use crate::batch::VerifiedClaimTransition;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::store::Store;
use crate::write_envelope::WriteActor;

/// The closer its typed lifecycle door verified, when this write is the
/// stored row's own exact close (only its lifecycle and `valid_to` change,
/// under a verified in-place transition). Such a close admits nothing new,
/// so the birth source's Auto permits are not renewed for it against the
/// unchanged provenance, and the Gate decides and receipts it as the closer:
/// revoking a birth permit later cannot block the close. Any other write,
/// and a close with no verified closer, answers `None` and keeps every
/// source-trust check under its envelope's actor.
pub(super) fn exact_close_closer(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> Option<WriteActor> {
    transition
        .and_then(VerifiedClaimTransition::closer)
        .filter(|_| super::closes_stored_row_only(store, txn, id, body, transition))
}
