//! The owner's answer in the reviewed run's one write: each member settled, the decision
//! recorded, and the settlement kept in the run's journal.

use super::members::{RunAnswer, SettledMember};
use super::*;

impl Memory<'_> {
    /// The settlement transaction's body; it returns the settlement, the
    /// gate metrics to record after commit, and the claims whose VAD
    /// consolidates then.
    pub(super) fn settle_reviewed_run_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        input: &RunSettleRequest,
        run: &String,
        approve: bool,
        now: u64,
    ) -> MemoryResult<(
        RunSettlement,
        Vec<crate::gate::RecordedClaimGateDecision>,
        Vec<EntityId>,
    )> {
        let (actor, review) = self.admit_run_settlement_in_txn(txn, owner, input, run)?;
        let owner_answer = owner.owner_answer_in_txn(self.vault(), txn)?;
        let answer = RunAnswer {
            owner,
            owner_answer: owner_answer.as_ref(),
            actor,
            approve,
            now,
        };
        let mut changes = Vec::new();
        let mut stored = Vec::new();
        let mut metrics = Vec::new();
        let mut vad = Vec::new();
        for (member, reviewed) in input.review.changes.iter().zip(&review.changes) {
            let SettledMember {
                verdict,
                receipt,
                inverse,
            } = self.settle_member_in_txn(
                txn,
                &answer,
                member,
                reviewed.verdict,
                &mut metrics,
                &mut vad,
            )?;
            changes.push(RunChangeOutcome {
                change: member.change().to_owned(),
                verdict,
                receipt,
            });
            stored.push(StoredChange {
                member: member.clone(),
                verdict,
                inverse,
                compensation: None,
                unrestored: Vec::new(),
            });
        }
        let reason = if approve {
            RunSettlementReason::OwnerApproved
        } else {
            RunSettlementReason::OwnerRejected
        };
        let record =
            self.record_settlement_decision_in_txn(txn, actor, &review, run, approve, now)?;
        let reference = format!("gate:{}", record.decision_id.to_hex());
        let settlement = owner_run_settlement(run, reference, changes, approve, reason);
        SETTLEMENTS.put(
            &self.vault().store,
            txn,
            run,
            &StoredRun {
                settlement: settlement.clone(),
                changes: stored,
            },
        )?;
        Ok((settlement, metrics, vad))
    }
}

/// The owner act's own durable word, not a caller-supplied person id or an
/// invented rule/grant attribution.
fn owner_run_settlement(
    run: &str,
    reference: String,
    changes: Vec<RunChangeOutcome>,
    approve: bool,
    reason: RunSettlementReason,
) -> RunSettlement {
    RunSettlement {
        kind: RunSettlementKind::ProposalOutcome,
        run_id: run.to_owned(),
        receipt: reference.clone(),
        verdict: if changes
            .iter()
            .any(|c| c.verdict == RunChangeVerdict::Waiting)
        {
            RunChangeVerdict::Waiting
        } else if approve {
            RunChangeVerdict::Landed
        } else {
            RunChangeVerdict::Rejected
        },
        changes,
        answered_by: RunAnsweredBy::Word {
            word_ref: reference,
        },
        reason,
        summary: if approve {
            "The owner accepted the reviewed changes."
        } else {
            "The owner rejected the waiting changes; earlier landings stay."
        }
        .to_owned(),
        revert_handle: format!("run:{run}"),
    }
}
