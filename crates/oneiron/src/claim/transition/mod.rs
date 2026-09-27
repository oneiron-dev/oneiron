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
