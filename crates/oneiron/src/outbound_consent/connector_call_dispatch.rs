//! A connector dispatch's outcome mapped to a call step and its reason codes.
//! Entry: `step_from_host`. Defines its own items.

use crate::connector_key::EffectorBudgetCharge;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentState, OutboundFailureKind, OutboundSendFailure,
    OutboundSendOutcome,
};

use super::connector_call::{
    ConnectorAwaitingInput, ConnectorCallHost, ConnectorResultAbsence, UntrustedToolResult,
};
use super::connector_call_driver::Step;
use super::execution::ScopedMcpDispatchResult;
use super::scope::{ScopedMcpConsentDecision, ScopedMcpEscalationReason};

/// The reason a call gets when its connector is now installed at another
/// endpoint than the one it froze: definitely never sent (FIX 2553).
const CONNECTOR_ENDPOINT_CHANGED: &str = "connector_endpoint_changed";

/// Maps one execute onto a step, with the reply and the questions `host`
/// kept for its send. Questions a step that is not Done leaves behind have
/// no caller to answer them, so the host ends them at once (FIX 3844). A
/// send the host held at its last binding read presented nothing, so the
/// call holds with the host's reason rather than counting as a failure.
pub(super) fn step_from_host<H: ConnectorCallHost>(
    dispatch: &ScopedMcpDispatchResult,
    host: &mut H,
) -> Step {
    let reply = host.take_result();
    let awaiting = host.take_awaiting_input();
    let handle = awaiting.as_ref().map(|input| input.handle.clone());
    let step = match host.take_send_hold() {
        Some(reason) => Step::Held {
            decision_ref: None,
            reasons: vec![reason.to_owned()],
            ask: None,
        },
        None => step_from_dispatch(dispatch, reply, awaiting),
    };
    if let Some(handle) = handle
        && !matches!(step, Step::AwaitingInput { .. })
    {
        host.abandon_awaiting_input(&handle);
    }
    step
}

/// Maps one execute onto a step. AutoFire alone proves nothing: only a Done
/// ledger row is delivery, and the gate's own outcome tells a hold from a
/// denial. A delivered send whose connector asked for input carries its
/// questions in place of a reply.
fn step_from_dispatch(
    dispatch: &ScopedMcpDispatchResult,
    reply: Option<UntrustedToolResult>,
    awaiting: Option<ConnectorAwaitingInput>,
) -> Step {
    let decision_ref = dispatch.gate_decision_ref().map(str::to_owned);
    let mut reasons: Vec<String> = Vec::new();
    for reason in dispatch.gate_reasons() {
        push_reason(&mut reasons, reason);
    }
    if let ScopedMcpConsentDecision::Escalate(reason) = dispatch.decision {
        push_reason(&mut reasons, escalation_code(reason));
    }
    if let Some(next_eligible_at) = dispatch.paced_until() {
        return Step::Paced {
            next_eligible_at,
            reasons,
        };
    }
    let denied = dispatch.gate_outcome() == Some("deny");
    let hold_or_deny = |mut reasons: Vec<String>, decision_ref: Option<String>| {
        if denied {
            if reasons.is_empty() {
                reasons.push("gate_denied".to_owned());
            }
            Step::Refused {
                decision_ref,
                reasons,
            }
        } else {
            if reasons.is_empty() {
                reasons.push("gate_held".to_owned());
            }
            Step::Held {
                decision_ref,
                reasons,
                ask: dispatch.held_ask().cloned(),
            }
        }
    };
    let Some(ledger) = dispatch.dispatch.as_ref() else {
        return hold_or_deny(reasons, decision_ref);
    };
    let escalation = ledger.escalation.map(|escalation| escalation.reason);
    if let Some(reason) = escalation {
        push_reason(&mut reasons, intent_escalation_code(reason));
    }
    match (ledger.state, ledger.intent_id) {
        (Some(IntentState::Done), intent) => match awaiting {
            Some(input) => Step::AwaitingInput { intent, input },
            None => Step::Delivered {
                intent,
                result_absence: reply
                    .is_none()
                    .then_some(ConnectorResultAbsence::NotRetained),
                result: reply,
                budget_steering: dispatch
                    .budget_charge
                    .as_ref()
                    .map(EffectorBudgetCharge::steering_messages)
                    .unwrap_or_default(),
            },
        },
        // A stop of a send that may have gone out (delivery left unresolved),
        // the owner's Stop included, is unsettled, never a refusal (FIX 7351,
        // FIX 9280).
        (Some(IntentState::Abandoned), Some(intent))
            if dispatch.delivery_unresolved()
                || matches!(
                    escalation,
                    Some(
                        IntentEscalationReason::NonIdempotentAmbiguous
                            | IntentEscalationReason::NonIdempotentPending
                    )
                ) =>
        {
            Step::Unsettled { intent, reasons }
        }
        // FIX 990: `never allow` stops the request; a send that may already
        // have reached the connector stays an unsettled delivery.
        (Some(IntentState::Abandoned), Some(intent))
            if escalation == Some(IntentEscalationReason::ConnectorSlateNeverAllow)
                && dispatch.delivery_unresolved() =>
        {
            Step::Unsettled { intent, reasons }
        }
        // FIX 7960: the connector took the call as a remote task. Its
        // outcome is still out, and it is never sent again.
        (Some(IntentState::Deferred), Some(intent)) => {
            push_reason(&mut reasons, REMOTE_TASK_DEFERRED);
            Step::Unsettled { intent, reasons }
        }
        (Some(IntentState::Abandoned), _) => {
            if reasons.is_empty() {
                reasons.push("abandoned".to_owned());
            }
            Step::Refused {
                decision_ref,
                reasons,
            }
        }
        (Some(IntentState::Pending), Some(intent)) => match ledger.send_outcome {
            Some(OutboundSendOutcome::Failed(OutboundSendFailure {
                kind: OutboundFailureKind::EndpointChanged,
                ..
            })) => {
                push_reason(&mut reasons, "delivery_failed");
                push_reason(&mut reasons, CONNECTOR_ENDPOINT_CHANGED);
                Step::NotDelivered { intent, reasons }
            }
            Some(OutboundSendOutcome::Failed(_)) => {
                push_reason(&mut reasons, "delivery_failed");
                Step::Retryable { intent, reasons }
            }
            Some(
                OutboundSendOutcome::Ambiguous
                | OutboundSendOutcome::Acked
                | OutboundSendOutcome::Deferred,
            ) => {
                push_reason(&mut reasons, "delivery_unconfirmed");
                Step::Retryable { intent, reasons }
            }
            None => hold_or_deny(reasons, decision_ref),
        },
        _ => hold_or_deny(reasons, decision_ref),
    }
}

/// The reason an unsettled call its connector took as a remote task names
/// (FIX 7960).
pub(super) const REMOTE_TASK_DEFERRED: &str = "remote_task_deferred";

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|known| known == reason) {
        reasons.push(reason.to_owned());
    }
}

pub(super) fn escalation_code(reason: ScopedMcpEscalationReason) -> &'static str {
    match reason {
        ScopedMcpEscalationReason::InvalidGrant => "invalid_grant",
        ScopedMcpEscalationReason::ToolDataClassNotGranted => "tool_data_class_not_granted",
        ScopedMcpEscalationReason::WrongPrincipal => "wrong_principal",
        ScopedMcpEscalationReason::WrongServer => "wrong_server",
        ScopedMcpEscalationReason::WrongTool => "wrong_tool",
        ScopedMcpEscalationReason::EndpointNotAllowed => "endpoint_not_allowed",
        ScopedMcpEscalationReason::UnknownDataClass => "unknown_data_class",
        ScopedMcpEscalationReason::DataClassCeilingExceeded => "data_class_ceiling_exceeded",
        ScopedMcpEscalationReason::ConnectorKeyUnregistered => "connector_key_unregistered",
        ScopedMcpEscalationReason::ConnectorKeyPending => "connector_key_pending",
        ScopedMcpEscalationReason::ConnectorKeySuspended => "connector_key_suspended",
        ScopedMcpEscalationReason::ConnectorKeyRevoked => "connector_key_revoked",
        ScopedMcpEscalationReason::ConnectorKeyCharterDrift => "charter_drift",
        ScopedMcpEscalationReason::ConnectorManifestDrift => "connector_manifest_drift",
        ScopedMcpEscalationReason::StaleConnectorManifest { .. } => "connector_manifest_stale",
        ScopedMcpEscalationReason::ConnectorKeyCharterNeverList => "charter_never_list",
        ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted => "effector_budget_exhausted",
        ScopedMcpEscalationReason::ConnectorSlateAlwaysAsk => "connector_key_slate_always_ask",
        ScopedMcpEscalationReason::ConnectorSlateNeverAllow => "connector_key_slate_never_allow",
    }
}

pub(super) fn intent_escalation_code(reason: IntentEscalationReason) -> &'static str {
    match reason {
        IntentEscalationReason::NonIdempotentAmbiguous => "non_idempotent_ambiguous",
        IntentEscalationReason::NonIdempotentPending => "non_idempotent_pending",
        IntentEscalationReason::ConnectorRevoked => "connector_revoked",
        IntentEscalationReason::BindingInvalid => "binding_invalid",
        IntentEscalationReason::PreviouslyAbandoned => "previously_abandoned",
        IntentEscalationReason::CorruptLedgerRow => "corrupt_ledger_row",
        IntentEscalationReason::DedupeReservationReplaced => "dedupe_reservation_replaced",
        IntentEscalationReason::DedupeSuppressed => "dedupe_suppressed",
        IntentEscalationReason::OwnerStopped => "owner_stopped",
        IntentEscalationReason::ConnectorSlateNeverAllow => "connector_key_slate_never_allow",
        IntentEscalationReason::ActorErased => "actor_erased",
        IntentEscalationReason::RecipientErased => "recipient_erased",
        IntentEscalationReason::OwnerErased => "owner_erased",
        IntentEscalationReason::RemoteTaskFailed => "remote_task_failed",
    }
}
