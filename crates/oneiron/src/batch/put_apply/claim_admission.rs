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
        Some(crate::claim::validate_claim_body_and_decode(
            input.data,
            input.allow_reserved_predicate,
        )?)
    } else {
        None
    };
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
