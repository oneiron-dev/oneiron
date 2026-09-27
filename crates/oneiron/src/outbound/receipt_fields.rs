use std::collections::BTreeMap;

use super::OutboundDeliveryWindowDecision;
use super::capability::OutboundVerbContract;
use super::connector_task::ConnectorSendTask;
use super::dispatch_pipeline::admission::AdmissionStage;
use super::dispatch_pipeline::verdict::DispatchVerdict;
use super::dispatch_types::{
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundDispatchResult,
};
use crate::channel_identity_autonomy::FrozenSpacePosting;
use crate::delivery_window::{DeliveryWindowMatch, DeliveryWindowResolution};
use crate::gate::ExternalEffectPolicyRisk;
use crate::gate::GateOutcome;
use crate::outbound::dispatch_pipeline::retry_after::{
    PROVIDER_RETRY_AFTER_FIELD, provider_retry_after_secs,
};
use crate::receipt::ReceiptRecord;
use crate::receipt::outbound_intent_receipt;

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

/// This exact receipt is committed by the common outbound admission writer.
/// A replay reads it back instead of recreating a second suppression decision.
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
    receipt
        .fields
        .insert("suppression".to_owned(), "dedupe".to_owned());
    receipt.fields.insert(
        "suppression_evidence".to_owned(),
        "replicated_observation".to_owned(),
    );
    receipt
        .policy_trace
        .push("outbound.dedupe.cooldown".to_owned());
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

/// Assemble the audit receipt and caller-visible result from one gate verdict.
pub(super) fn dispatch_result_receipt(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
    space_posting: Option<&FrozenSpacePosting>,
    admission: &AdmissionStage,
    verdict: DispatchVerdict,
) -> OutboundDispatchResult {
    let DispatchVerdict {
        gate_decision_ref,
        gate_outcome,
        gate_reason_codes,
        gate_receipt_reasons,
        effector_charge,
        effect_state,
        outcome,
        execution,
        suppression_receipt,
    } = verdict;
    let gate_outcome_kind = gate_outcome;
    let gate_outcome = gate_outcome_kind.as_str().to_owned();
    if let Some(receipt) = suppression_receipt {
        return OutboundDispatchResult {
            outcome,
            gate_decision_id: gate_decision_ref,
            gate_outcome,
            gate_reason_codes,
            receipt,
            effector_budget: None,
            budget_ladder_events: Vec::new(),
        };
    }
    let window_decision = &admission.window_decision;
    let window_resolution = &admission.window_resolution;
    let mut engine_receipt_fields = BTreeMap::new();
    let mut engine_policy_trace = Vec::new();
    if let Some(posting) = space_posting {
        engine_receipt_fields.insert(
            "space_posting".to_owned(),
            posting.preset_token().to_owned(),
        );
        engine_receipt_fields.insert(
            "space_posting_setting_ref".to_owned(),
            posting.setting_ref().to_owned(),
        );
        engine_receipt_fields.insert(
            "space_posting_policy_risk".to_owned(),
            posting.policy_risk().to_string(),
        );
    }
    if let Some(seat) = admission.seat.as_ref() {
        engine_receipt_fields.extend(seat.receipt_fields.clone());
        engine_policy_trace.extend(seat.policy_trace.iter().cloned());
    }
    let mut receipt = outbound_intent_receipt(
        request.receipt_id.clone(),
        request.intent_ref.clone(),
        &request.intent,
        request.occurred_at,
        outcome.as_str(),
    );
    receipt
        .policy_trace
        .extend(gate_reason_codes.iter().cloned());
    receipt
        .policy_trace
        .extend(gate_receipt_reasons.iter().cloned());
    receipt.policy_trace.push(window_decision.policy_trace());
    receipt.policy_trace.extend(engine_policy_trace);
    if let Some(gate_decision_ref) = gate_decision_ref.as_deref() {
        receipt
            .fields
            .insert("gate_decision_ref".to_owned(), gate_decision_ref.to_owned());
    }
    receipt
        .fields
        .insert("gate_outcome".to_owned(), gate_outcome.clone());
    receipt
        .fields
        .insert("gate_reason_codes".to_owned(), gate_reason_codes.join(","));
    if !gate_receipt_reasons.is_empty() {
        receipt.fields.insert(
            "gate_receipt_reasons".to_owned(),
            gate_receipt_reasons.join(","),
        );
    }
    // The provider's own stated cool-down, normalized to whole seconds and
    // stamped beside the gate evidence rather than mixed into it. Only a
    // well-formed value is promoted: the connector's raw string still
    // reaches the receipt verbatim through
    // `append_execution_receipt_fields`, so this adds a machine-readable
    // re-arm authority without editing what the provider actually said.
    if let Some(retry_after) = execution.as_ref().and_then(provider_retry_after_secs) {
        receipt.fields.insert(
            PROVIDER_RETRY_AFTER_FIELD.to_owned(),
            retry_after.to_string(),
        );
    }
    if let Some(effect_state) = effect_state {
        receipt
            .fields
            .insert("intent_state".to_owned(), effect_state.as_str().to_owned());
    }
    // GOV-02 (ONE-1418) budget legibility: stamped only when a governing
    // connector key's budget stage ran. `budget_debit`/`budget` are the
    // exact fields the RS4 receipt projections already sum. A refused
    // send stamps `budget_debit: "0"` next to the deny reason — the
    // honest record. `budget` = min remaining over the rows MATCHED by
    // this dispatch (the binding constraint — M4 resolution 2026-07-10).
    if let Some(charge) = effector_charge.as_ref() {
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
    receipt.fields.insert(
        "channel_call".to_owned(),
        verb_contract.channel_call.clone(),
    );
    receipt.fields.insert(
        "interruption_class".to_owned(),
        serde_json::to_value(&verb_contract.interruption_class)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
    );
    receipt.fields.insert(
        "retry_class".to_owned(),
        serde_json::to_value(&verb_contract.retry_class)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
    );
    receipt.fields.insert(
        "policy_risk".to_owned(),
        match policy_risk {
            ExternalEffectPolicyRisk::Normal => "normal",
            ExternalEffectPolicyRisk::HoldToProposal => "hold_to_proposal",
        }
        .to_owned(),
    );
    for (key, value) in engine_receipt_fields {
        receipt.fields.insert(key, value);
    }
    append_optional_receipt_field(
        &mut receipt,
        "content_ref",
        request.intent.content_ref.as_deref(),
    );
    append_optional_receipt_field(
        &mut receipt,
        "idempotency_key",
        request.intent.idempotency_key.as_deref(),
    );
    append_optional_receipt_field(
        &mut receipt,
        "dedupe_key",
        request.intent.dedupe_key.as_deref(),
    );
    append_optional_receipt_field(
        &mut receipt,
        "channel_identity_ref",
        request
            .channel_identity_ref
            .map(|identity_ref| identity_ref.to_hex())
            .as_deref(),
    );
    append_optional_receipt_field(
        &mut receipt,
        "counterparty_ref",
        request.counterparty_ref.as_deref(),
    );
    if let Some(execution) = execution {
        receipt.fields.insert(
            "delivery_may_have_occurred".to_owned(),
            execution.delivery_may_have_occurred.to_string(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "provider_ref",
            execution.provider_ref.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "retry_state",
            execution.retry_state.as_deref(),
        );
        append_execution_receipt_fields(&mut receipt, &execution.receipt_fields);
    }
    append_dispatch_outcome_receipt_fields(
        &mut receipt,
        outcome,
        gate_outcome_kind,
        &gate_reason_codes,
        &gate_receipt_reasons,
    );
    append_window_receipt_fields(&mut receipt, window_decision);
    append_window_resolution_receipt_fields(&mut receipt, window_resolution, window_decision);
    if let Some(context) = request.context_receipt.as_ref() {
        context.append_to_fields(&mut receipt.fields);
    }

    let (effector_budget, budget_ladder_events) = match effector_charge {
        Some(charge) => (Some(charge.read), charge.ladder_events),
        None => (None, Vec::new()),
    };
    OutboundDispatchResult {
        outcome,
        gate_decision_id: gate_decision_ref,
        gate_outcome,
        gate_reason_codes,
        receipt,
        effector_budget,
        budget_ladder_events,
    }
}
