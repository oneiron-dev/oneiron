//! Whether a claim write only closes its stored row, under a verified
//! in-place transition: the checks the claim door and its closer share.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, VerifiedClaimTransition};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body, encode_claim_body};
use crate::entity_id::EntityId;
use crate::ports::EntityStoreRead;
use crate::store::Store;

/// Whether this write only closes the stored row: the row's own value, now
/// closed, under a verified in-place transition. It admits nothing new, so no
/// checker is consulted and none is required, whatever the value's length: a
/// restriction always lands.
pub(super) fn closes_stored_value(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    closes_in_place(store, txn, id, body, transition)
        && stored_claim_body(store, txn, id).is_some_and(|stored| stored.value == body.value)
}

/// Whether this write is the stored row's own close and nothing more: the
/// stored Active body with only its lifecycle and `valid_to` changed, as the
/// canonical lifecycle validator admits it. An edit that also moves approval
/// or any other field is not one.
pub(super) fn closes_stored_row_only(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    closes_in_place(store, txn, id, body, transition)
        && stored_claim_body(store, txn, id).is_some_and(|mut stored| {
            if stored.lifecycle != ClaimLifecycleStatus::Active {
                return false;
            }
            stored.lifecycle = body.lifecycle;
            stored.valid_to = body.valid_to;
            match (encode_claim_body(&stored), encode_claim_body(body)) {
                (Ok(closed), Ok(written)) => closed == written,
                _ => false,
            }
        })
}

/// A non-Active body under a verified in-place transition of the same row.
fn closes_in_place(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    body.lifecycle != ClaimLifecycleStatus::Active
        && transition.is_some_and(|proof| {
            proof.predecessor().is_none()
                && proof.matches_body(store, txn, id, body).unwrap_or(false)
        })
}

/// The stored row's claim body, when it decodes.
fn stored_claim_body(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Option<ClaimBody> {
    let raw = store.port_entity_record(txn, id).ok().flatten()?.encode();
    decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()
}
