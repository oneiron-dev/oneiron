use std::collections::{HashMap, VecDeque};

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// One preflight verdict, bound to its operation receipt inside the same transaction.
#[derive(Debug, Clone)]
pub(crate) struct StagedClaimGateOutcome {
    pub(crate) decision_id: crate::store::GateDecisionId,
    pub(crate) outcome: crate::gate::GateOutcome,
    pub(crate) reason_codes: Vec<crate::gate::GateReasonCode>,
    pub(crate) diff_handle: Vec<u8>,
    pub(crate) read_frontier_hash: [u8; 32],
    pub(crate) created_at: u64,
}

/// Bind preflight outcomes to receipt identities, not claim IDs. Phase 2 takes
/// the identity from its per-claim operation FIFO, including empty slots, so
/// repeated IDs cannot borrow another operation's verdict.
pub(super) fn staged_claim_gate_outcomes(
    staged_decisions: &[crate::gate::RecordedClaimGateDecision],
) -> HashMap<crate::store::GateDecisionId, StagedClaimGateOutcome> {
    let mut staged = HashMap::new();
    for decision in staged_decisions {
        let record = decision.record();
        if record
            .receipt_reasons
            .iter()
            .any(|reason| reason == crate::gate::GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED)
        {
            continue;
        }
        staged.insert(
            record.decision_id,
            StagedClaimGateOutcome {
                decision_id: record.decision_id,
                outcome: decision.decision().outcome(),
                reason_codes: decision.decision().reason_codes().to_vec(),
                diff_handle: record.diff_handle.clone(),
                read_frontier_hash: record.read_frontier_hash,
                created_at: record.created_at,
            },
        );
    }
    staged
}

/// Books ONE preflight-eligible write's gate decision and, on a refusal,
/// preserves exactly its denial receipt while discarding the transaction's
/// earlier allow receipts.
///
/// Shared by both preflight shapes — one decision per Put/ClaimCandidate op,
/// and one per instance inside a `CommitmentGapDecay` op — so a lapse denial
/// survives rollback through the same path every other local CLAIM write uses.
pub(super) fn stage_preflight_decision(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    eligible_id: &EntityId,
    recorded_decision: Option<crate::gate::RecordedClaimGateDecision>,
    result: Result<()>,
    staged_decisions: &mut Vec<crate::gate::RecordedClaimGateDecision>,
    preflight_gate_decision_ids: &mut HashMap<
        EntityId,
        VecDeque<Option<crate::store::GateDecisionId>>,
    >,
) -> Result<()> {
    let decision_id = recorded_decision
        .as_ref()
        .map(crate::gate::RecordedClaimGateDecision::decision_id);
    if let Some(decision) = recorded_decision {
        staged_decisions.push(decision);
    }
    // Keep one FIFO slot for every preflight-eligible operation. A None
    // slot prevents an earlier non-receipt claim sharing this id from
    // consuming a later claim's receipt identity.
    preflight_gate_decision_ids
        .entry(*eligible_id)
        .or_default()
        .push_back(decision_id);
    if let Err(err) = result {
        let preserved_denial_id = staged_decisions
            .last()
            .filter(|decision| {
                Some(decision.decision_id()) == decision_id && decision.outcome() != "allow"
            })
            .map(crate::gate::RecordedClaimGateDecision::decision_id);
        for decision in staged_decisions.iter().rev() {
            if Some(decision.decision_id()) != preserved_denial_id {
                store.delete_gate_decision_in_txn(wtxn, decision.decision_id())?;
            }
        }
        staged_decisions.retain(|decision| Some(decision.decision_id()) == preserved_denial_id);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
