use std::collections::BTreeMap;

use super::OutboundDeliveryWindowDecision;
use super::connector_task::ConnectorSendTask;
use super::dispatch_types::{OutboundDispatchOutcome, OutboundDispatchRequest};
use crate::connector_key::EffectorBudgetCharge;
use crate::delivery_window::{DeliveryWindowMatch, DeliveryWindowResolution};
use crate::gate::GateOutcome;
use crate::receipt::{ReceiptRecord, outbound_intent_receipt};

pub(super) fn append_optional_receipt_field(
    receipt: &mut ReceiptRecord,
    key: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value
        && !value.trim().is_empty()
    {
        receipt.fields.insert(key.to_owned(), value.to_owned());
    }
}

/// The semantic floor is separate from the Gate decision: a Gate allow can
/// still collapse an already-delivered intent without fabricating a deny code.
pub(super) fn append_dedupe_suppression_receipt_fields(
    receipt: &mut ReceiptRecord,
    dedupe_suppressed: bool,
) {
    if dedupe_suppressed {
        receipt
            .fields
            .insert("suppression".to_owned(), "dedupe".to_owned());
        receipt
            .policy_trace
            .push("outbound.dedupe.cooldown".to_owned());
    }
}

/// Receipt bytes the common writer door commits on semantic suppression.
/// The same row is returned on first admission and on exact replay.
pub(super) fn suppression_receipt_for_dispatch(
    request: &OutboundDispatchRequest,
    decision: &OutboundDeliveryWindowDecision,
    resolution: &DeliveryWindowResolution,
) -> Option<ReceiptRecord> {
    request
        .intent
        .dedupe_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())?;
    let mut receipt = outbound_intent_receipt(
        request.receipt_id.clone(),
        request.intent_ref.clone(),
        &request.intent,
        request.occurred_at,
        "suppressed",
    );
    append_dedupe_suppression_receipt_fields(&mut receipt, true);
    // Peers receive the observation as an ASSET, never the device-local
    // ledger authority that decided suppression.
    receipt.fields.insert(
        "suppression_evidence".to_owned(),
        "replicated_observation".to_owned(),
    );
    receipt.policy_trace.push(decision.policy_trace());
    receipt
        .fields
        .insert("gate_outcome".to_owned(), "allow".to_owned());
    receipt
        .fields
        .insert("gate_reason_codes".to_owned(), "gate.allow".to_owned());
    append_window_receipt_fields(&mut receipt, decision);
    append_window_resolution_receipt_fields(&mut receipt, resolution, decision);
    if let Some(context) = request.context_receipt.as_ref() {
        context.append_to_fields(&mut receipt.fields);
    }
    Some(receipt)
}

pub(super) fn append_execution_receipt_fields(
    receipt: &mut ReceiptRecord,
    fields: &BTreeMap<String, String>,
) {
    for (key, value) in fields {
        if key.trim().is_empty() || value.trim().is_empty() {
            continue;
        }
        receipt
            .fields
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

pub(super) fn append_dispatch_outcome_receipt_fields(
    receipt: &mut ReceiptRecord,
    outcome: OutboundDispatchOutcome,
    gate_outcome: GateOutcome,
    gate_reason_codes: &[String],
    gate_receipt_reasons: &[String],
) {
    let gate_reason = gate_reason_codes
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map(String::as_str);
    let gate_receipt_reason = gate_receipt_reasons
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map(String::as_str);

    match (outcome, gate_outcome) {
        (OutboundDispatchOutcome::Held, GateOutcome::Pending) => {
            append_optional_receipt_field(receipt, "hold_reason", gate_reason);
        }
        (OutboundDispatchOutcome::Suppressed, GateOutcome::Deny) => {
            let suppression = if gate_reason_codes
                .iter()
                .any(|reason| reason == "gate.deny.counterparty_opt_out")
            {
                "counterparty_opt_out"
            } else {
                "gate_denied"
            };
            receipt
                .fields
                .insert("suppression".to_owned(), suppression.to_owned());
            append_optional_receipt_field(
                receipt,
                "suppression_reason",
                gate_receipt_reason.or(gate_reason),
            );
        }
        _ => {}
    }
}

/// Stamps the TASK's frozen clock provenance onto an execution receipt. Only
/// the snapshot travels here; the policy verdict stays live.
pub(super) fn append_connector_task_window_receipt(
    receipt: &mut ReceiptRecord,
    task: &ConnectorSendTask,
) {
    if let Some(offset) = task.utc_offset_minutes {
        receipt
            .fields
            .insert("utc_offset_minutes".to_owned(), offset.to_string());
    }
    if let Some(zone) = task.iana_timezone.as_ref() {
        receipt
            .fields
            .insert("iana_timezone".to_owned(), zone.clone());
    }
    if task.human_explicit_instant {
        receipt
            .fields
            .insert("human_explicit_instant".to_owned(), "true".to_owned());
    }
    if let Some(level) = task.resolved_level {
        receipt
            .fields
            .insert("resolved_level".to_owned(), level.as_str().to_owned());
    }
}

fn window_action(decision: &OutboundDeliveryWindowDecision) -> &'static str {
    match decision {
        OutboundDeliveryWindowDecision::DeliverNow
        | OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => "deliver_now",
        OutboundDeliveryWindowDecision::Hold { .. } => "hold",
        OutboundDeliveryWindowDecision::Degrade { .. } => "degrade",
        OutboundDeliveryWindowDecision::LetGo { .. } => "let_go",
    }
}

/// Writes the policy observation separately from the action ultimately taken.
/// This matters for human-explicit sends: the hold is observed, but execution
/// is allowed — and the standing claim still lands in the audit row.
///
/// Every field comes from the ONE resolution the door already enforced, so the
/// receipt cannot drift from the decision, and the rung string is rendered
/// only through [`DeliveryWindowLadderRung::as_str`] — no out-of-enum rung
/// name can be invented here.
pub(super) fn append_window_resolution_receipt_fields(
    receipt: &mut ReceiptRecord,
    resolution: &DeliveryWindowResolution,
    effective: &OutboundDeliveryWindowDecision,
) {
    receipt.fields.insert(
        "window_observed_action".to_owned(),
        window_action(&resolution.observed).to_owned(),
    );
    receipt.fields.insert(
        "window_effective_action".to_owned(),
        window_action(effective).to_owned(),
    );
    receipt.fields.insert(
        "window_ladder_rung".to_owned(),
        resolution.rung.as_str().to_owned(),
    );
    receipt.fields.insert(
        "window_match".to_owned(),
        canonical_window_match_evidence(&resolution.matched),
    );
}

/// Canonicalizes the repeated match evidence into one stable receipt string:
/// deduplicated and sorted, so two receipts over the same live claim set are
/// byte-identical regardless of claim read order.
fn canonical_window_match_evidence(matched: &[DeliveryWindowMatch]) -> String {
    if matched.is_empty() {
        return "none".to_owned();
    }
    let mut predicates = matched
        .iter()
        .map(|entry| entry.predicate.clone())
        .collect::<Vec<_>>();
    predicates.sort_unstable();
    predicates.dedup();
    predicates.join(",")
}

pub(super) fn append_window_receipt_fields(
    receipt: &mut ReceiptRecord,
    decision: &OutboundDeliveryWindowDecision,
) {
    match decision {
        OutboundDeliveryWindowDecision::DeliverNow => {
            receipt
                .fields
                .insert("window_action".to_owned(), "deliver_now".to_owned());
        }
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { reason, from, to } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "deliver_now".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("degraded_from".to_owned(), from.clone());
            receipt.fields.insert("degraded_to".to_owned(), to.clone());
        }
        OutboundDeliveryWindowDecision::Hold { reason, retry_at } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "hold".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .entry("hold_reason".to_owned())
                .or_insert_with(|| reason.clone());
            if let Some(retry_at) = retry_at {
                receipt
                    .fields
                    .insert("retry_at".to_owned(), retry_at.to_string());
            }
        }
        OutboundDeliveryWindowDecision::Degrade { reason, from, to } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "degrade".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("degraded_from".to_owned(), from.clone());
            receipt.fields.insert("degraded_to".to_owned(), to.clone());
        }
        OutboundDeliveryWindowDecision::LetGo { reason } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "let_go".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("let_go_reason".to_owned(), reason.clone());
        }
    }
}

/// GOV-02 meter evidence is stamped only when a connector key governed the
/// effect. The binding minimum is the one constraint the receipt can report.
pub(super) fn append_budget_charge_receipt_fields(
    receipt: &mut ReceiptRecord,
    charge: Option<&EffectorBudgetCharge>,
) {
    if let Some(charge) = charge {
        receipt.fields.insert(
            "connector_key_ref".to_owned(),
            format!("ckey:{}", charge.key_ref.to_hex()),
        );
        receipt
            .fields
            .insert("budget_debit".to_owned(), charge.sends_debit.to_string());
        let binding_remaining = charge
            .read
            .rows
            .iter()
            .filter(|row| charge.matched_rows.contains(&row.row_index))
            .map(|row| row.remaining)
            .min();
        if let Some(binding_remaining) = binding_remaining {
            receipt
                .fields
                .insert("budget".to_owned(), binding_remaining.to_string());
        }
    }
}
