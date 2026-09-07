use std::collections::{HashMap, VecDeque};

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// ONE-1453: what `BatchBuilder::commit`'s gate PREFLIGHT already decided for
/// one local claim, carried into phase-2 materialization.
///
/// It exists because breaker accounting is booked exactly once, at the site
/// that appends the event's ordinary decision. Phase 2 must therefore reuse
/// that verdict rather than evaluate policy a second time — a second
/// evaluation would either debit the breaker twice or silently discard the
/// demotion the first one computed.
///
/// This is NOT a general gate-bypass argument: it is crate-private, it is
/// built only from decisions this same transaction staged, and the door that
/// consumes it enforces rather than re-evaluates.
#[derive(Debug, Clone)]
pub(crate) struct StagedClaimGateOutcome {
    pub(crate) decision_id: crate::store::GateDecisionId,
    pub(crate) outcome: crate::gate::GateOutcome,
    pub(crate) reason_codes: Vec<crate::gate::GateReasonCode>,
    pub(crate) diff_handle: Vec<u8>,
    pub(crate) read_frontier_hash: [u8; 32],
    pub(crate) created_at: u64,
    /// The breaker converted this claim's would-be-`Auto` outcome, so phase 2
    /// enforces against `Proposed` and re-encodes the stored body to match.
    pub(crate) breaker_demoted: bool,
}

/// Bind breaker outcomes to receipt identities, not claim IDs. Phase 2 takes
/// the identity from its per-claim operation FIFO, including empty slots, so
/// repeated IDs cannot borrow another operation's verdict.
pub(super) fn staged_claim_gate_outcomes(
    staged_decisions: &[crate::gate::RecordedClaimGateDecision],
) -> HashMap<crate::store::GateDecisionId, StagedClaimGateOutcome> {
    let mut staged = HashMap::new();
    for decision in staged_decisions {
        if !decision.breaker_demoted() && decision.breaker_undo().is_none() {
            continue;
        }
        let record = decision.record();
        staged.insert(
            record.decision_id,
            StagedClaimGateOutcome {
                decision_id: record.decision_id,
                outcome: decision.decision().outcome(),
                reason_codes: decision.decision().reason_codes().to_vec(),
                diff_handle: record.diff_handle.clone(),
                read_frontier_hash: record.read_frontier_hash,
                created_at: record.created_at,
                breaker_demoted: decision.breaker_demoted(),
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
        // ONE-1453: walk the discarded decisions in REVERSE staging order.
        // Order is load-bearing when several earlier claims touched the same
        // actor/run row: each undo restores the exact bytes ITS event
        // observed, so unwinding last-to-first lands the row back on the byte
        // state that preceded the first staged claim. Forward order would
        // leave an intermediate snapshot behind.
        for decision in staged_decisions.iter().rev() {
            // An error materializes no claim, even when its pending/denial
            // receipt is retained. Undo accounting and trip receipts first.
            if let Some(undo) = decision.breaker_undo() {
                crate::gate::undo_gate_breaker_in_txn(store, wtxn, undo)?;
            }
            if Some(decision.decision_id()) != preserved_denial_id {
                store.delete_gate_decision_in_txn(wtxn, decision.decision_id())?;
            }
        }
        staged_decisions.retain(|decision| Some(decision.decision_id()) == preserved_denial_id);
        return Err(err);
    }
    Ok(())
}

/// Re-encode the staged Auto-to-Proposed conversion before body hashing and
/// storage planning. All other reconciliation keeps its existing order.
pub(super) fn demote_claim_body(
    staged: Option<&StagedClaimGateOutcome>,
    body: &mut Option<crate::claim::ClaimBody>,
) -> Result<Option<Vec<u8>>> {
    if !staged.is_some_and(|staged| staged.breaker_demoted) {
        return Ok(None);
    }
    let demoted = body
        .as_mut()
        .ok_or(crate::error::Error::InvariantViolation(
            "validated CLAIM body missing",
        ))?;
    demoted.approval = crate::claim::ClaimApprovalStatus::Proposed;
    Ok(Some(crate::claim::encode_claim_body(demoted)?))
}

#[cfg(test)]
mod tests;
