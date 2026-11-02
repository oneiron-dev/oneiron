//! Claim-body and immutable-ledger admission before any put side effect.
use crate::claim::ClaimBody;
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
    pub(super) posture: crate::HostingPrivacyPosture,
    pub(super) transition: Option<&'a crate::batch::VerifiedClaimTransition>,
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
        Some(crate::claim::validate_claim_body_and_decode_in_txn(
            store,
            txn,
            input.data,
            input.allow_reserved_predicate,
        )?)
    } else {
        None
    };
    crate::claim::history_store::validate_machine_history_put(
        store,
        txn,
        crate::claim::history_store::MachineHistoryPut {
            id: &id,
            entity_type: input.entity_type,
            occurred: input.occurred,
            learned_at: input.learned_at,
            data: input.data,
            body: body.as_ref(),
            replicated: input.replicated,
            posture: input.posture,
        },
    )?;
    if let Some(body) = &body {
        // The typed citations the evidence carries are read once here, in
        // their recognized slots: a malformed one is a malformed body.
        body.evidence_refs()?;
        crate::comm::guard_send_override_put(
            body,
            input.allow_reserved_predicate,
            input.replicated,
        )?;
        crate::authority::verify_machine_claim_in_txn(
            store,
            txn,
            input.posture,
            &id,
            body,
            input.replicated,
            input.write_envelope,
        )?;
    }
    crate::booking::publication::guard_publication_put(store, txn, id, body.as_ref())?;
    crate::workspace_roster::guard_goal_claim_put(
        store,
        txn,
        id,
        body.as_ref(),
        input.data,
        input.replicated,
    )?;
    if let Some(body) = &body {
        // Replay applies the CRDT's current head, not every intermediate
        // consent/demotion transition. Structural validation above still runs;
        // local confidence admission needs a predecessor only on local writes.
        if !input.replicated {
            crate::write_envelope::carry_forward::validate_admission(
                store,
                txn,
                &id,
                body,
                crate::write_envelope::carry_forward::CarryForwardAdmission {
                    envelope: input.write_envelope,
                    transition: input.transition,
                    occurred: input.occurred,
                    learned_at: input.learned_at,
                },
            )?;
        }
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

/// The MESSAGE body check every put of row `id` meets before it stages.
/// `own_device` is the lane the sync ingest door gave a replicated row one of
/// the owner's own machines sent (FIX 9600); it counts only for this row and
/// these exact bytes.
pub(super) fn validate_witness_message_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
    replicated: bool,
    own_device: Option<&super::request::VerifiedOwnDeviceLane>,
) -> Result<()> {
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
    if replicated && let Some(machine) = own_device.and_then(|lane| lane.machine_for(id, data)) {
        // FIX 9600: one of the owner's own machines sent these exact bytes
        // at this id, over a connection that proved the machine. The
        // own-device door admits the author buckets this store can bind and
        // refuses the rest as the door below does. A lane that vouches for
        // another row or other bytes is no lane: the row meets the door below.
        crate::gate::validate_own_device_witness_message_body(store, txn, machine, data)?;
    } else if replicated {
        // The REPLICATED road has no actor to run the ceiling against and,
        // without a lane, no verified sender: a federated, recovered or
        // unknown replay fails closed for every author bucket (see
        // `gate::validate_replicated_witness_message_body`).
        crate::gate::validate_replicated_witness_message_body(data)?;
    } else {
        crate::gate::validate_canonical_witness_message_body(data)?;
    }
    Ok(())
}

/// Whether `reader` may put a row at `id` in `txn` (FIX 6068): an id that
/// names no stored row is free to take; an occupied one only when its
/// original row, whatever it holds (a deleted, retained or other-kind row
/// included), is one `reader` reads. Judged before any incoming body, scope
/// stamp or edge can change what the row means.
pub(crate) fn put_target_admitted_in(
    reader: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !crate::ports::EntityStoreRead::port_entity_present(&reader.vault().store, txn, id)? {
        return Ok(true);
    }
    match reader.is_entity_readable_in(txn, id) {
        Err(error) if error.kind() == crate::ErrorKind::InvalidSecretCustodyBody => Ok(false),
        readable => readable,
    }
}
