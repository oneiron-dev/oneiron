//! The verified closer of an exact lifecycle close (FIX 8655).

use crate::batch::VerifiedClaimTransition;
use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::store::Store;
use crate::write_envelope::{WriteActor, WriteEnvelope};

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

/// The actor the Gate judges, ceilings and receipts a write as: the verified
/// `closer` of an exact close, whether or not the stored row carries a birth
/// envelope, else the `envelope`'s actor. The owner's close of a row put with
/// no envelope is the owner's, not a first-party write (review 10097 P1).
/// `None` for a write with neither.
pub(super) fn writing_actor(
    closer: Option<WriteActor>,
    envelope: Option<&WriteEnvelope>,
) -> Option<WriteActor> {
    closer.or_else(|| envelope.map(WriteEnvelope::actor))
}

/// Whether a write is derivation-class, held to the derivation floors
/// (GATE-12, GATE-13, the checker): its `envelope` is a Dreamer run's or a
/// `vault.derive` commit's, and no human `closer` closes the row. The birth
/// envelope names who derived the row, not who closes it, so the owner's
/// exact close of a Dreamer claim is not held to the Dreamer's floors
/// (review 10097 P1; GATE-13: owner and human writes never enter).
pub(super) fn derivation_class(
    envelope: Option<&WriteEnvelope>,
    closer: Option<WriteActor>,
) -> bool {
    envelope.is_some_and(super::derivation_class_write)
        && !closer.is_some_and(|closer| closer.actor_class() == EdgeActorClass::Human)
}
