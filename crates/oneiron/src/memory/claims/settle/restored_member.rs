//! One member of an owner restore's inbox group, settled on the
//! `vault.claims.settle` path (RULING 02:26 13 Nov, NOTE
//! ARCHIVE-RESTORE-APPROVE-DESIGN R3, R4). The member is read as a review
//! reads it, with the owner's restore left out of its openers (D5), and
//! settles with its own owner proof and its own Settlement receipt. A member
//! the owner opened, or whose approval would supersede a live head, is left
//! waiting; so is one the gate refuses or holds. The caller settles each
//! member in its own savepoint and drops the savepoint of one left waiting.

use super::*;
use crate::inbox::{OpenRestoredMember, RestoreMemberWait, RestoredMemberSettle};
use crate::ports::TombstoneStoreRead;

fn waiting(
    wait: RestoreMemberWait,
    replaces: Option<EntityId>,
    detail: Option<String>,
) -> RestoredMemberSettle {
    RestoredMemberSettle::Waiting {
        wait,
        replaces,
        detail,
    }
}

impl crate::Vault {
    /// The body of the restored claim `id` while it is an open proposal in
    /// `txn`: not deleted, Proposed and Active. `None` when it is settled,
    /// closed, deleted or gone.
    fn open_restored_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> crate::Result<Option<ClaimBody>> {
        if self.store.port_deletion_state(txn, id)?.deleted {
            return Ok(None);
        }
        Ok(self.get_claim_in_txn(txn, id)?.filter(|body| {
            body.approval == ClaimApprovalStatus::Proposed
                && body.lifecycle == ClaimLifecycleStatus::Active
        }))
    }

    /// The restore group `members` still open in `txn`, in their order, each
    /// with the live head its approval would supersede, as a review of it
    /// binds that head. The claims about each subject are read once for all
    /// the members (R6).
    pub(crate) fn open_restored_members_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        members: &[EntityId],
    ) -> crate::Result<Vec<OpenRestoredMember>> {
        let mut heads = ConflictHeadIndex::default();
        let mut open = Vec::new();
        for id in members {
            let Some(body) = self.open_restored_claim_in_txn(txn, id)? else {
                continue;
            };
            let replaces = if self.has_deferred_claim_in_txn(txn, id)? {
                None
            } else {
                heads.head_id(self, txn, id, &body)?
            };
            open.push(OpenRestoredMember { id: *id, replaces });
        }
        Ok(open)
    }
}

impl Memory<'_> {
    /// Settles the restored claim `id` by `action` as the owner `actor`, whose
    /// proof `owner` answers the claim's owner-answer obligation, in `wtxn`, the
    /// member's own savepoint: the gate decides it as `vault.claims.settle`
    /// does, and it appends its own Settlement receipt. An approval never
    /// supersedes a live head here; that member waits.
    ///
    /// # Errors
    ///
    /// A store failure, or an owner proof that no longer holds.
    pub(crate) fn settle_restored_member_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        actor: WriteActor,
        id: EntityId,
        action: GateConsentBundleAction,
        now: u64,
    ) -> MemoryResult<RestoredMemberSettle> {
        // The review read below binds the live head, so this check reads none.
        if self
            .vault
            .open_restored_claim_in_txn(&*wtxn, &id)?
            .is_none()
        {
            return Ok(RestoredMemberSettle::Closed);
        }
        let reviewed = ReviewedProposal::read_in_txn(self.vault, &*wtxn, &id)?;
        if reviewed.openers.contains(&actor.entity_ref()) {
            return Ok(waiting(RestoreMemberWait::OpenedByOwner, None, None));
        }
        if action == GateConsentBundleAction::Approve
            && let Some(prior) = &reviewed.prior
        {
            return Ok(waiting(
                RestoreMemberWait::ReplacesLiveHead,
                Some(prior.id),
                None,
            ));
        }
        if let Err(error) =
            reviewed.settleable(&reviewed.review_id(), actor.entity_ref(), action, false)
        {
            return Ok(waiting(
                RestoreMemberWait::Refused,
                None,
                Some(error.message),
            ));
        }
        let owner_answer = owner.owner_answer_in_txn(self.vault, &*wtxn)?;
        let settled = match self.vault.settle_proposed_claim_in_txn(
            wtxn,
            id,
            action,
            actor,
            owner_answer,
            now,
        ) {
            Ok(settled) => settled,
            Err(error @ Error::Gate(_)) => {
                return Ok(waiting(
                    RestoreMemberWait::Refused,
                    None,
                    Some(MemoryError::from(error).message),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        // The approval's commit carries its consolidation debt (FIX 11858).
        if action == GateConsentBundleAction::Approve && settled.dreamer_run {
            self.vault.owe_settled_claim_vads_in_txn(wtxn, &[id])?;
        }
        let (outcome, reason) = match action {
            GateConsentBundleAction::Approve => ("approved", ClaimSettlementReason::OwnerApproved),
            GateConsentBundleAction::Decline => ("rejected", ClaimSettlementReason::OwnerDeclined),
        };
        let mut record = crate::memory::authorship::decision(
            actor,
            CLAIM_SETTLEMENT_CONTENT_KIND,
            outcome,
            reason.as_str(),
            Some(id),
            reviewed.digest.to_vec(),
            now,
        );
        record.read_frontier_hash = reviewed.frontier;
        // FIX 7499, 7500: the member's read context, and the loop links of
        // the pending decision it answers.
        let pending = reviewed.pending.as_ref().and_then(|pending| {
            self.vault
                .store
                .gate_decision_in_txn(&*wtxn, pending.decision_id)
                .ok()
                .flatten()
        });
        record.context = crate::store::GateDecisionContext {
            read: crate::store::GateDecisionReadContext::claim(&id, &reviewed.body)
                .map(|read| {
                    read.with_anchors(crate::conversation::gate_claim_anchors_in(
                        self.vault,
                        &*wtxn,
                        &id,
                        &reviewed.body,
                    ))
                })
                .into_iter()
                .collect(),
            ..pending
                .as_ref()
                .map(crate::store::GateDecisionContext::answering)
                .unwrap_or_default()
        };
        self.vault
            .store
            .append_gate_decision_in_txn(wtxn, &record)?;
        Ok(RestoredMemberSettle::Settled {
            receipt: record,
            recorded: settled.recorded,
            dreamer_run: settled.dreamer_run,
        })
    }
}
