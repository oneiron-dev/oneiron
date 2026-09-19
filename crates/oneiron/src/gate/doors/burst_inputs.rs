//! Native write observations from same-actor claim decision receipts.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::GateReasonCode;
use crate::llm::{NormalizedBurstInputs, normalized_burst_inputs};
use crate::store::Store;

/// Reads, never debits. Earlier receipts in the caller's transaction contribute
/// exactly once. If that transaction rolls back, no auxiliary rate state can
/// survive it. Owner and other-actor decisions cannot inflate this baseline.
///
/// The ledger is streamed with constant retained memory. Only known structural
/// precommit failures extend the streak. Policy holds and checker outages are
/// neutral; successful claim writes reset it. Runtime failures that produce no
/// claim receipt are not inferred from free-form error strings.
pub(super) fn claim_burst_inputs(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    now: u64,
) -> Result<NormalizedBurstInputs> {
    let actor_ref = actor.to_hex();
    let mut writes = 0_u64;
    let mut first = now;
    let mut latest = None;
    let mut current_tick_writes = 0_u64;
    let mut streak = 0_u32;
    let structural_reasons = [
        GateReasonCode::DenyDreamerDegenerateOutput.as_str(),
        GateReasonCode::DenyDreamerMalformed.as_str(),
        GateReasonCode::DenyDreamerNoEvidence.as_str(),
    ];
    store.for_each_gate_decision_in_txn(txn, |record| {
        if record.actor_class != "agent"
            || record.actor_ref.as_deref() != Some(actor_ref.as_str())
            || record.content_kind != "claim"
            || record.claim_id.is_none()
        {
            return Ok(());
        }
        if record.outcome == "allow" {
            let at = record.created_at.min(now);
            writes = writes.saturating_add(1);
            first = first.min(at);
            latest = Some(latest.map_or(at, |last: u64| last.max(at)));
            if at == now {
                current_tick_writes = current_tick_writes.saturating_add(1);
            }
            streak = 0;
        } else if record.outcome == "deny"
            && record
                .reason_codes
                .iter()
                .any(|reason| structural_reasons.contains(&reason.as_str()))
        {
            streak = streak.saturating_add(1);
        }
        Ok(())
    })?;
    // The recent observation includes this candidate. The ledger timestamp's
    // seconds resolution supplies the minimum measurable interval, not a limit.
    let window = latest.map_or(1, |last| now.saturating_sub(last).max(1));
    let recent = current_tick_writes.saturating_add(1);
    let baseline = writes as f64 / now.saturating_sub(first).max(1) as f64;
    Ok(normalized_burst_inputs(
        recent,
        window,
        baseline,
        store.entities.len(txn)?,
        streak,
    ))
}
