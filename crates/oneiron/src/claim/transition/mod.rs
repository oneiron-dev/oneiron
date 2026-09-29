//! Signed, causally ordered claim state transitions. Birth content is never rewritten.

mod event;
mod fold;
mod write;

pub(crate) use event::{
    ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta,
    decode_machine_claim_transition_event, encode_machine_claim_transition_event,
    machine_claim_transition_event_hash, machine_claim_transition_event_id,
    machine_claim_transition_transcript, verify_machine_claim_transition_event,
};
pub(crate) use fold::{
    ClaimTransitionProjection, TransitionFoldError, fold_machine_claim_transitions,
};
pub(crate) use write::stage_machine_claim_transition;

#[cfg(test)]
use event::TransitionEventHash;
#[cfg(test)]
mod tests;

/// Stage an authenticated actor's typed decision without relabeling it as
/// MACHINE authorship. The caller has already enforced verb-specific authority
/// (owner approval, exact keyed self-grant, or an explicit delegation).
pub(crate) fn stage_machine_transition_as(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: crate::EntityId,
    kind: ClaimTransitionKind,
    delta: TransitionDelta,
    actor: crate::WriteActor,
    now: u64,
) -> crate::Result<crate::ClaimBody> {
    stage_machine_claim_transition(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        id,
        kind,
        delta,
        actor.entity_ref(),
        actor.actor_class(),
        crate::TimeRange {
            start: now,
            end: now,
        },
        now,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

/// Owner consent on a MACHINE claim's pending Gate row: approval signs an
/// Approve event and a decline a Reject event, which the fold never retracts.
/// Returns the projection the live row must carry.
pub(crate) fn stage_consent_transition(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: crate::EntityId,
    approve: bool,
    actor: crate::WriteActor,
    now: u64,
) -> crate::Result<crate::ClaimBody> {
    let kind = if approve {
        ClaimTransitionKind::Approve
    } else {
        ClaimTransitionKind::Reject
    };
    stage_machine_transition_as(vault, txn, id, kind, TransitionDelta::None, actor, now)
}

/// Existing owner-typed lifecycle doors carry no separate actor argument;
/// their host-root action is attributed to the vault's embedded owner.
/// Actor-bound memory/inbox doors can pass their authenticated actor directly
/// to `stage_machine_claim_transition` instead.
pub(crate) fn stage_owner_machine_transition(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: crate::EntityId,
    kind: ClaimTransitionKind,
    delta: TransitionDelta,
    now: u64,
) -> crate::Result<crate::ClaimBody> {
    let actor = crate::vault::embedded_owner_actor_id()?;
    stage_machine_claim_transition(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        id,
        kind,
        delta,
        actor,
        crate::edge::EdgeActorClass::Human,
        crate::TimeRange {
            start: now,
            end: now,
        },
        now,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

/// Close a MACHINE-born claim through its signed history; any other claim is
/// returned unchanged. `actor` is the typed door's authenticated writer, and
/// `None` attributes the close to the vault's embedded owner.
pub(crate) fn close_machine_claim_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: crate::EntityId,
    closed: crate::ClaimBody,
    kind: ClaimTransitionKind,
    now: u64,
    actor: Option<crate::WriteActor>,
) -> crate::Result<crate::ClaimBody> {
    if !crate::authority::machine_claim_needs_history(&vault.store, txn, &closed)? {
        return Ok(closed);
    }
    let delta = TransitionDelta::ValidTo(now);
    match actor {
        Some(writer) => stage_machine_transition_as(vault, txn, id, kind, delta, writer, now),
        None => stage_owner_machine_transition(vault, txn, id, kind, delta, now),
    }
}

/// Owner-bound approval of a proposed MACHINE claim. The original MACHINE
/// signature stays on its immutable birth; the host signs a distinct Approve
/// event, and the existing typed materialization/Gate still decides consent.
impl crate::Vault {
    pub fn approve_machine_claim_as(
        &self,
        id: crate::EntityId,
        actor: crate::WriteActor,
    ) -> crate::Result<()> {
        self.with_write_txn(|txn| {
            self.verify_owner_write_actor_in_txn(txn, &actor)?;
            let body = self
                .get_claim_in_txn(txn, &id)?
                .ok_or(crate::Error::EntityNotFound)?;
            if !crate::authority::machine_claim_needs_history(&self.store, txn, &body)?
                || body.approval != crate::claim::ClaimApprovalStatus::Proposed
                || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
            {
                return Err(crate::Error::InvalidClaimBody(
                    "machine approval requires active proposal",
                ));
            }
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(crate::Error::EntityNotFound)?
                .to_vec();
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(crate::Error::CorruptedIndex("machine claim header"))?;
            let mut approved = body;
            approved.approval = crate::claim::ClaimApprovalStatus::Approved;
            crate::batch::ClaimMaterialization::apply_approval(
                self,
                txn,
                crate::batch::BatchOp::Put {
                    id,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: crate::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    learned_at: header.learned_at,
                    data: crate::claim::encode_claim_body(&approved)?,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                true,
                Some(actor),
            )
        })
    }
}
