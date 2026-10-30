//! Outbound receipt field projection.
//! Entry: `dispatch_result_receipt`.
//! Defines its own items.

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

/// FIX 6424 (Engine 10-20 20:4x): the receipt field a held send's
/// approve-once digest rides, beside its gate outcome.
pub(crate) const APPROVAL_DIGEST_FIELD: &str = "approval_digest";

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
/// `approval_digest` is the approve-once digest the Gate composed for the
/// send's effect, carried only while the Gate holds it (FIX 6424); the
/// holding decision's own digest, from the chokepoint, names it when set (a
/// co-actor's hold, FIX 6424 part 2a).
pub(super) fn dispatch_result_receipt(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
    space_posting: Option<&FrozenSpacePosting>,
    admission: Option<&AdmissionStage>,
    verdict: DispatchVerdict,
    approval_digest: Option<String>,
) -> OutboundDispatchResult {
    let DispatchVerdict {
        gate_decision_ref,
        gate_outcome,
        gate_reason_codes,
        gate_receipt_reasons,
        effector_charge,
        effect_state,
        resolution,
        outcome,
        execution,
        suppression_receipt,
        // Already folded into the admission's seat decision by the pipeline.
        ceiling_count: _,
        held_approval_digest,
        held_approval_actor,
        provider_wait,
        provider_wait_held_until,
        paced_until,
        budget_reservation,
    } = verdict;
    let gate_outcome_kind = gate_outcome;
    let gate_outcome = gate_outcome_kind.as_str().to_owned();
    // FIX 6424: a send the Gate holds for the owner names the digest his
    // approve-once press on it must carry, and (part 2a) whose press it is.
    let (approval_digest, approval_actor) = match held_approval_digest {
        Some(digest) => (Some(digest), held_approval_actor),
        None => (approval_digest, request.actor.actor_entity_ref),
    };
    let approval_digest = approval_digest.filter(|_| gate_outcome_kind == GateOutcome::Pending);
    let approval_actor = approval_actor.filter(|_| approval_digest.is_some());
    if let Some(receipt) = suppression_receipt {
        return OutboundDispatchResult {
            outcome,
            gate_decision_id: gate_decision_ref,
            gate_outcome,
            gate_reason_codes,
            approval_digest,
            approval_actor,
            receipt,
            resolution,
            effector_budget: None,
            budget_ladder_events: Vec::new(),
            budget_pool: None,
        };
    }
    let window_decision = admission.map(|stage| &stage.window_decision);
    let window_resolution = admission.map(|stage| &stage.window_resolution);
    let (engine_receipt_fields, engine_policy_trace) =
        engine_receipt_evidence(space_posting, admission);
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
    if let Some(window_decision) = window_decision {
        receipt.policy_trace.push(window_decision.policy_trace());
    }
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
    append_optional_receipt_field(
        &mut receipt,
        APPROVAL_DIGEST_FIELD,
        approval_digest.as_deref(),
    );
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
    append_effector_budget_receipt(&mut receipt, effector_charge.as_ref());
    append_settlement_receipt_fields(
        &mut receipt,
        provider_wait,
        provider_wait_held_until,
        budget_reservation,
    );
    // FIX 7948: a send a full window paces names the instant it comes back,
    // which its executor re-arms at, and the window it waits for.
    if let Some(edge) = paced_until {
        receipt
            .fields
            .insert("retry_at".to_owned(), edge.to_string());
        append_optional_receipt_field(
            &mut receipt,
            "hold_reason",
            gate_reason_codes.first().map(String::as_str),
        );
    }
    append_contract_receipt(&mut receipt, verb_contract, policy_risk);
    for (key, value) in engine_receipt_fields {
        receipt.fields.insert(key, value);
    }
    append_request_receipt(&mut receipt, request);
    // FIX 7965: every failed or uncertain receipt names a typed next step.
    let recovery_suggestions = super::recovery_suggestions::recovery_suggestions_for(
        outcome,
        execution.as_ref(),
        execution.as_ref().and_then(provider_retry_after_secs),
        request.occurred_at,
    );
    super::recovery_suggestions::append_recovery_suggestions(&mut receipt, &recovery_suggestions);
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
    if let (Some(window_resolution), Some(window_decision)) = (window_resolution, window_decision) {
        append_window_receipt_fields(&mut receipt, window_decision);
        append_window_resolution_receipt_fields(&mut receipt, window_resolution, window_decision);
    }
    if let Some(context) = request.context_receipt.as_ref() {
        context.append_to_fields(&mut receipt.fields);
    }

    let (effector_budget, budget_ladder_events, budget_pool) = match effector_charge {
        Some(charge) => (Some(charge.read), charge.ladder_events, charge.pool),
        None => (None, Vec::new(), None),
    };
    OutboundDispatchResult {
        outcome,
        gate_decision_id: gate_decision_ref,
        gate_outcome,
        gate_reason_codes,
        approval_digest,
        approval_actor,
        receipt,
        resolution,
        effector_budget,
        budget_ladder_events,
        budget_pool,
    }
}

/// Receipt field naming the kind of provider wait a queued send keeps (FIX
/// 8818).
pub(crate) const PROVIDER_WAIT_FIELD: &str = "provider_wait";

/// Receipt field naming where a send's reserved budget stands (FIX 7964).
const BUDGET_RESERVATION_FIELD: &str = "budget_reservation";

/// What the ledger keeps beside a send's row, on its receipt: the provider
/// wait it is queued for (FIX 8818), the edge that wait held this dispatch
/// at as its `retry_at` when nothing went, and its reserved budget's status
/// (FIX 7964).
fn append_settlement_receipt_fields(
    receipt: &mut ReceiptRecord,
    provider_wait: Option<crate::outbound_intent_ledger::ProviderRetryDirective>,
    provider_wait_held_until: Option<u64>,
    budget_reservation: Option<crate::outbound_intent_ledger::ReservationStatus>,
) {
    if let Some(wait) = provider_wait {
        receipt.fields.insert(
            PROVIDER_WAIT_FIELD.to_owned(),
            wait.kind.as_str().to_owned(),
        );
    }
    if let Some(edge) = provider_wait_held_until {
        receipt
            .fields
            .insert("retry_at".to_owned(), edge.to_string());
    }
    if let Some(status) = budget_reservation {
        receipt.fields.insert(
            BUDGET_RESERVATION_FIELD.to_owned(),
            status.as_str().to_owned(),
        );
    }
}

/// The engine's own receipt evidence for a dispatch: the frozen space
/// posting's fields and the seat decision's fields and policy trace.
fn engine_receipt_evidence(
    space_posting: Option<&FrozenSpacePosting>,
    admission: Option<&AdmissionStage>,
) -> (BTreeMap<String, String>, Vec<String>) {
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
    if let Some(seat) = admission.and_then(|stage| stage.seat.as_ref()) {
        engine_receipt_fields.extend(seat.receipt_fields.clone());
        engine_policy_trace.extend(seat.policy_trace.iter().cloned());
    }
    (engine_receipt_fields, engine_policy_trace)
}

/// Stamps the governing connector key's budget charge on the receipt.
fn append_effector_budget_receipt(
    receipt: &mut ReceiptRecord,
    effector_charge: Option<&crate::connector_key::EffectorBudgetCharge>,
) {
    if let Some(charge) = effector_charge {
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
            .filter(|row| charge.matched_rows.contains(&row.row))
            .map(|row| row.remaining)
            .min();
        if let Some(binding_remaining) = binding_remaining {
            receipt
                .fields
                .insert("budget".to_owned(), binding_remaining.to_string());
        }
        // ONE-1794: a per-grant key's catalog pool, beside the key's own
        // echo and under the catalog key's ref. Stamped only when the pool's
        // stage ran; `budget_debit` stays the key's own, so the receipt
        // projections never count one send twice.
        if let Some(pool) = charge.pool.as_ref() {
            receipt.fields.insert(
                "budget_pool_key_ref".to_owned(),
                format!("ckey:{}", pool.key_ref.to_hex()),
            );
            receipt
                .fields
                .insert("budget_pool_debit".to_owned(), pool.sends_debit.to_string());
            let pool_remaining = charge.read.pool.as_ref().and_then(|read| {
                read.rows
                    .iter()
                    .filter(|row| pool.matched_rows.contains(&row.row))
                    .map(|row| row.remaining)
                    .min()
            });
            if let Some(pool_remaining) = pool_remaining {
                receipt
                    .fields
                    .insert("budget_pool".to_owned(), pool_remaining.to_string());
            }
        }
    }
}

/// Stamps the verb contract's channel call, interruption and retry classes
/// and the policy risk on the receipt.
fn append_contract_receipt(
    receipt: &mut ReceiptRecord,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
) {
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
}

/// Stamps the request's optional content, idempotency, dedupe, identity and
/// counterparty references on the receipt.
fn append_request_receipt(receipt: &mut ReceiptRecord, request: &OutboundDispatchRequest) {
    append_optional_receipt_field(
        receipt,
        "content_ref",
        request.intent.content_ref.as_deref(),
    );
    append_optional_receipt_field(
        receipt,
        "idempotency_key",
        request.intent.idempotency_key.as_deref(),
    );
    append_optional_receipt_field(receipt, "dedupe_key", request.intent.dedupe_key.as_deref());
    append_optional_receipt_field(
        receipt,
        "channel_identity_ref",
        request
            .channel_identity_ref
            .map(|identity_ref| identity_ref.to_hex())
            .as_deref(),
    );
    append_optional_receipt_field(
        receipt,
        "counterparty_ref",
        request.counterparty_ref.as_deref(),
    );
}
