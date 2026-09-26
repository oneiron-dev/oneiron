//! Claim-body and immutable-ledger admission before any put side effect.
use super::ENTITY_METADATA_HEADER_LEN;
use crate::claim::ClaimBody;
use crate::error::{Error, RecordError};
use crate::store::Store;
use crate::{EntityId, Result, TimeRange, WriteEnvelope};

pub(super) struct ClaimPutAdmission<'a> {
    pub(super) entity_type: u8,
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) data: &'a [u8],
    pub(super) allow_reserved_predicate: bool,
    pub(super) write_envelope: Option<&'a WriteEnvelope>,
    pub(super) replicated: bool,
}

pub(super) fn admit_claim_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    input: ClaimPutAdmission<'_>,
) -> Result<Option<ClaimBody>> {
    crate::federation::guard_ruling_overwrite(
        store,
        txn,
        &id,
        input.entity_type,
        input.occurred,
        input.learned_at,
        input.data,
    )?;
    let body = if input.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        Some(crate::claim::validate_claim_body_and_decode(
            input.data,
            input.allow_reserved_predicate,
        )?)
    } else {
        None
    };
    crate::booking::publication::guard_publication_put(store, txn, id, body.as_ref())?;
    if let Some(body) = &body {
        crate::scope_summary::merge_summary_ref(body)?;
        crate::federation::validate_ruling_claim(
            store,
            txn,
            &id,
            body,
            input.learned_at,
            input.write_envelope,
            input.replicated,
        )?;
    }
    Ok(body)
}

// The ledger is immutable birth identity, never a second text plane. This
// shared guard covers local writes and replicated/window rematerialization.
pub(super) fn validate_note_birth_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    crate::note::decode_note_body_in_txn(store, txn, data)?;
    if let Some(old) = store.entities.get(txn, id.as_bytes())?
        && old.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
    {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "NOTE birth body is immutable",
        )));
    }
    Ok(())
}

pub(super) fn validate_witness_message_body(data: &[u8], replicated: bool) -> Result<()> {
    // ONE-1686 (RT-04): the witness ENVELOPE law, at the one arm every
    // road to a MESSAGE body converges on — the witness door, promote
    // replay, and sync rematerialization alike. The AUTHORITY half
    // (which actor may write which author bucket) is answered before
    // staging by `gate::check_witness_message_ceiling`, which is the only
    // way to reach `BatchBuilder::put_witness_message`; what is left
    // for a chokepoint that holds bytes and no actor is proving the bytes
    // ARE the canonical envelope those axes encode. A local row already
    // is one by construction (the put consumes the door's own output), so
    // this costs the witness path nothing and closes every other road.
    //
    // Placed BEFORE any store mutation in this function, so a refusal on
    // either road leaves nothing partial behind for the caller's
    // quarantine-and-continue to clean up.
    if replicated {
        // The REPLICATED road has no actor to run the ceiling against and
        // the protocol carries no verified source actor or peer signer at
        // this door, so it fails closed for every author bucket: see
        // `gate::validate_replicated_witness_message_body`.
        crate::gate::validate_replicated_witness_message_body(data)?;
    } else {
        crate::gate::validate_canonical_witness_message_body(data)?;
    }
    Ok(())
}
