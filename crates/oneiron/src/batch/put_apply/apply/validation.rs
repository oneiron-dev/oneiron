use super::*;

// The ledger is immutable birth identity, never a second text plane. This
// shared guard covers local writes and replicated/window rematerialization.
pub(super) fn validate_note_birth_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    crate::note::decode_note_body_in_txn(store, txn, data)?;
    if let Some(old) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
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
    // way to reach `TxnBatchBuilder::put_witness_message`; what is left
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

pub(super) fn decode_previous_skill_record(
    old_type: u8,
    old_record: &[u8],
) -> Result<Option<crate::skill::SkillRecord>> {
    if old_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
    match crate::skill::decode_skill_record(prior_body) {
        Ok(record) => Ok(Some(record)),
        Err(error)
            if error.kind() == ErrorKind::InvalidSkillBody
                && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
