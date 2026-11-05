//! An interrupt's ambient alternative owns its TASK's send once admitted
//! (FIX 11029). The alternative's own ledger row, found by the identity it
//! derives from the TASK's logical send, decides each later attempt: gone
//! (delivered, or accepted as a remote task), the TASK completes as the
//! degraded send it was; live, the same alternative goes again through its
//! own Gate, window and ledger key, whatever the interrupt's window says
//! now; stopped with its delivery unknown, the TASK is ambiguous. Only an
//! alternative never admitted, or stopped definitely unsent, leaves the
//! interrupt its own route. The interrupt never sends while its
//! alternative may still go or may have gone.

use super::*;
use crate::outbound::OutboundAmbientAlternative;
use crate::outbound::dispatch_pipeline::{
    ambient_alternative_dispatch_request, ambient_alternative_ref, name_ambient_alternative,
};
use crate::outbound::retry_audit::settle_ambiguous_alternative_task;
use crate::outbound_intent_ledger::{ConnectorIntentBinding, reconcile_connector_intent_in_txn};

/// How one claimed attempt went, routed by its alternative.
pub(super) enum RoutedAttempt {
    /// The alternative leaves the interrupt its own route.
    Interrupt,
    /// The alternative went: the TASK's send is carried out.
    Went,
    /// The attempt is settled or re-armed; the interrupt did not go.
    Settled,
}

/// What the alternative's own ledger row says of the TASK's route.
enum AlternativeRoute {
    /// Never admitted, or stopped definitely unsent.
    Open,
    /// Delivered, or accepted as a remote task.
    Went,
    /// Admitted and not settled.
    Live,
    /// Stopped with its delivery unknown.
    Uncertain,
}

/// Routes one claimed attempt of `task` by its bound alternative's ledger
/// row before its interrupt `request` is dispatched.
pub(super) fn route_bound_alternative<S: OutboundExecutionSink>(
    vault: &Vault,
    sink: &mut S,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    request: &OutboundDispatchRequest,
    now: u64,
) -> Result<RoutedAttempt, ConnectorTaskExecutorError> {
    let Some(alternative) = request.ambient_alternative.as_deref() else {
        return Ok(RoutedAttempt::Interrupt);
    };
    match alternative_route(vault, task, alternative, now)? {
        AlternativeRoute::Open => Ok(RoutedAttempt::Interrupt),
        AlternativeRoute::Went => {
            let receipt =
                interrupt_receipt(request, task, alternative, ALTERNATIVE_WENT_EARLIER, now);
            complete_degraded_connector_task(vault, attempt, task, receipt, now)?;
            Ok(RoutedAttempt::Went)
        }
        AlternativeRoute::Uncertain => {
            let receipt =
                interrupt_receipt(request, task, alternative, ALTERNATIVE_STOPPED_UNKNOWN, now);
            settle_ambiguous_alternative_task(vault, attempt, task, receipt, now)?;
            Ok(RoutedAttempt::Settled)
        }
        AlternativeRoute::Live => {
            send_live_alternative(vault, sink, queue, attempt, task, request, alternative)
        }
    }
}

/// What the interrupt's receipt says of an alternative that went on an
/// earlier attempt.
const ALTERNATIVE_WENT_EARLIER: &str = "went_earlier";
/// What it says of one that stopped with its delivery unknown.
const ALTERNATIVE_STOPPED_UNKNOWN: &str = "stopped_delivery_unknown";

/// The route the alternative's ledger row gives: its call 0, bound to the
/// alternative's own intent and counterparty and the TASK's actor and
/// session, read and reduced in one writer.
fn alternative_route(
    vault: &Vault,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    now: u64,
) -> Result<AlternativeRoute, Error> {
    let ledger_ref = ambient_alternative_ref(
        &connector_logical_send_intent_ref(task),
        &alternative.surface,
    );
    let attempt_id =
        super::super::dispatch_attempt_id::outbound_dispatch_attempt_id(&ledger_ref)
            .map_err(|_| Error::InvariantViolation("invalid ambient alternative ledger ref"))?;
    let binding = ConnectorIntentBinding {
        intent: &alternative.intent,
        actor_ref: task.actor_ref,
        actor_class: task.actor_class.gate_actor_class(),
        counterparty_ref: alternative.counterparty_ref.as_deref(),
        originating_session_ref: task.originating_session_ref.as_deref(),
        calendar_invite: None,
    };
    let resolution = vault.with_write_txn_grouped(|wtxn| {
        reconcile_connector_intent_in_txn(vault, wtxn, attempt_id, &binding, None, now).map_err(
            |_| Error::InvariantViolation("ambient alternative frozen ledger binding mismatch"),
        )
    })?;
    Ok(match resolution {
        None => AlternativeRoute::Open,
        Some(IntentResolution::Delivered | IntentResolution::Deferred) => AlternativeRoute::Went,
        Some(IntentResolution::Pending { .. }) => AlternativeRoute::Live,
        // A remote task that failed after its provider accepted it may have
        // done its work first.
        Some(IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::DefiniteNonDelivery,
            reason,
        }) if reason != IntentEscalationReason::RemoteTaskFailed => AlternativeRoute::Open,
        Some(IntentResolution::Stopped { .. }) => AlternativeRoute::Uncertain,
    })
}

/// Sends a live alternative again: the TASK completes when it goes, waits on
/// its edge when it is held, and is tried again otherwise, its own row
/// deciding the next attempt.
fn send_live_alternative<S: OutboundExecutionSink>(
    vault: &Vault,
    sink: &mut S,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    request: &OutboundDispatchRequest,
    alternative: &OutboundAmbientAlternative,
) -> Result<RoutedAttempt, ConnectorTaskExecutorError> {
    let child_request = ambient_alternative_dispatch_request(request, alternative);
    let dispatched = vault
        .dispatch_outbound_intent_with_verified_actor(
            child_request,
            sink,
            task.actor_ref,
            task.actor_class,
        )
        .and_then(|child| {
            crate::receipt::record_direct_dispatch_receipt(vault, child.receipt.clone())?;
            Ok(child)
        });
    // The transport ran inside dispatch: the settlement reads the clock
    // again (FIX 10955).
    let now = vault.now_recorded_at();
    let Ok(child) = dispatched else {
        retry_connector_task_attempt(
            queue,
            attempt,
            now,
            "ambient_alternative_dispatch_uncertain",
            None,
        )?;
        return Ok(RoutedAttempt::Settled);
    };
    match child.outcome {
        OutboundDispatchOutcome::DeliveredToChannel | OutboundDispatchOutcome::Deferred => {
            let receipt =
                interrupt_receipt(request, task, alternative, child.outcome.as_str(), now);
            complete_degraded_connector_task(vault, attempt, task, receipt, now)?;
            Ok(RoutedAttempt::Went)
        }
        OutboundDispatchOutcome::Held | OutboundDispatchOutcome::Degraded => {
            // The interrupt's attempt waits on the alternative's edge.
            let mut receipt =
                interrupt_receipt(request, task, alternative, child.outcome.as_str(), now);
            for field in ["retry_at", PROVIDER_RETRY_AFTER_FIELD, PROVIDER_WAIT_FIELD] {
                if let Some(value) = child.receipt.fields.get(field) {
                    receipt.fields.insert(field.to_owned(), value.clone());
                }
            }
            let mut parked = child;
            parked.receipt = receipt;
            settle_held_connector_task(vault, queue, attempt, task.task_ref, task, parked, now)?;
            Ok(RoutedAttempt::Settled)
        }
        _ => {
            let reason = format!("ambient_alternative_{}", child.outcome.as_str());
            retry_connector_task_attempt(
                queue,
                attempt,
                now,
                &reason,
                receipt_provider_retry_after(&child.receipt),
            )?;
            Ok(RoutedAttempt::Settled)
        }
    }
}

/// The interrupt's receipt for an attempt its alternative carried: degraded,
/// naming the alternative and what came of it.
fn interrupt_receipt(
    request: &OutboundDispatchRequest,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    outcome: &str,
    now: u64,
) -> crate::receipt::ReceiptRecord {
    let mut receipt = crate::receipt::outbound_intent_receipt(
        request.receipt_id.clone(),
        request.intent_ref.clone(),
        &task.intent,
        now,
        OutboundDispatchOutcome::Degraded.as_str(),
    );
    name_ambient_alternative(&mut receipt, request, alternative, outcome);
    receipt
}
