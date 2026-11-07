//! An interrupt's ambient alternative owns its TASK's send once admitted
//! (FIX 11029). The alternative's own ledger row, found by the identity it
//! derives from the TASK's logical send, decides each later attempt: gone
//! (delivered, or accepted as a remote task), the TASK completes as the
//! degraded send it was; live, the same alternative goes again through its
//! own Gate, window and ledger key, whatever the interrupt's window says
//! now; stopped with its delivery unknown, or live while the interrupt's own
//! admitted send is unresolved too, the TASK is ambiguous. Only an
//! alternative never admitted, or stopped definitely unsent, leaves the
//! interrupt its own route. The interrupt never sends while its alternative
//! may still go or may have gone. The row is read and the TASK settled on
//! it in one writer; the transport runs outside any writer.

use super::*;
use crate::attempt_queue::AttemptId;
use crate::outbound::OutboundAmbientAlternative;
use crate::outbound::dispatch_pipeline::{
    ambient_alternative_dispatch_request, ambient_alternative_ref, name_ambient_alternative,
};
use crate::outbound::retry_audit::{
    complete_degraded_connector_task_in_txn, settle_ambiguous_alternative_task_in_txn,
};
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
#[derive(Clone, Copy)]
enum AlternativeRoute {
    /// Never admitted, or stopped definitely unsent.
    Open,
    /// Never admitted while the interrupt's own admitted send is unresolved:
    /// the interrupt goes again alone.
    InterruptAlone,
    /// Delivered, or accepted as a remote task.
    Went,
    /// Admitted and not settled.
    Live,
    /// Stopped with its delivery unknown, or live beside an unresolved
    /// admitted interrupt.
    Uncertain,
}

/// What the interrupt's receipt says of an alternative that went on an
/// earlier attempt.
const ALTERNATIVE_WENT_EARLIER: &str = "went_earlier";
/// The interrupt receipt field naming the alternative's ledger identity.
const ALTERNATIVE_LEDGER_REF_FIELD: &str = "alternative_ledger_ref";
/// What it says of one that stopped with its delivery unknown.
const ALTERNATIVE_STOPPED_UNKNOWN: &str = "stopped_delivery_unknown";
/// The child receipt fields an interrupt's settlement reads its retry edge
/// and delivery evidence from.
const CARRIED_CHILD_FIELDS: [&str; 4] = [
    "retry_at",
    "delivery_may_have_occurred",
    PROVIDER_RETRY_AFTER_FIELD,
    PROVIDER_WAIT_FIELD,
];

/// Routes one claimed attempt of `task` by its bound alternative's ledger
/// row before its interrupt `request` is dispatched. An interrupt whose own
/// admitted send is unresolved, with no alternative admitted, goes with no
/// alternative bound: should its window degrade it again, no first
/// alternative goes beside a send that may have gone.
pub(super) fn route_bound_alternative<S: OutboundExecutionSink>(
    vault: &Vault,
    sink: &mut S,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    request: &mut OutboundDispatchRequest,
    now: u64,
) -> Result<RoutedAttempt, ConnectorTaskExecutorError> {
    let Some(alternative) = request.ambient_alternative.as_deref() else {
        return Ok(RoutedAttempt::Interrupt);
    };
    let went = interrupt_receipt(
        request,
        task,
        alternative,
        ALTERNATIVE_WENT_EARLIER,
        None,
        now,
    );
    let unknown = interrupt_receipt(
        request,
        task,
        alternative,
        ALTERNATIVE_STOPPED_UNKNOWN,
        None,
        now,
    );
    let route = vault.with_write_txn_grouped(|wtxn| {
        let route = alternative_route_in_txn(vault, wtxn, task, alternative, now)?;
        match route {
            AlternativeRoute::Went => {
                complete_degraded_connector_task_in_txn(vault, wtxn, attempt, task, went, now)?;
            }
            AlternativeRoute::Uncertain => {
                settle_ambiguous_alternative_task_in_txn(vault, wtxn, attempt, task, unknown, now)?;
            }
            AlternativeRoute::Open | AlternativeRoute::InterruptAlone | AlternativeRoute::Live => {}
        }
        Ok(route)
    })?;
    match route {
        // The interrupt's first admission names its bound alternative and is
        // refused should that be admitted meanwhile (an executor whose lease
        // ran out sending it).
        AlternativeRoute::Open => Ok(RoutedAttempt::Interrupt),
        AlternativeRoute::InterruptAlone => {
            request.ambient_alternative = None;
            Ok(RoutedAttempt::Interrupt)
        }
        AlternativeRoute::Went => Ok(RoutedAttempt::Went),
        AlternativeRoute::Uncertain => Ok(RoutedAttempt::Settled),
        AlternativeRoute::Live => {
            send_live_alternative(vault, sink, queue, attempt, task, request, alternative)
        }
    }
}

/// The alternative's ledger attempt and the exact binding its call 0 was
/// admitted under: its own intent and counterparty, the TASK's actor, class
/// and session, no invite.
fn alternative_identity<'a>(
    task: &'a ConnectorSendTask,
    alternative: &'a OutboundAmbientAlternative,
) -> Result<(AttemptId, ConnectorIntentBinding<'a>), Error> {
    let ledger_ref = ambient_alternative_ref(
        &connector_logical_send_intent_ref(task),
        &alternative.surface,
    );
    let attempt_id =
        super::super::dispatch_attempt_id::outbound_dispatch_attempt_id(&ledger_ref)
            .map_err(|_| Error::InvariantViolation("invalid ambient alternative ledger ref"))?;
    Ok((
        attempt_id,
        ConnectorIntentBinding {
            intent: &alternative.intent,
            actor_ref: task.actor_ref,
            actor_class: task.actor_class.gate_actor_class(),
            counterparty_ref: alternative.counterparty_ref.as_deref(),
            originating_session_ref: task.originating_session_ref.as_deref(),
            calendar_invite: None,
        },
    ))
}

/// The route the alternative's ledger row gives, read and reduced in `wtxn`.
/// A live alternative beside an interrupt whose own admitted send is
/// unresolved is uncertain: either may have gone.
fn alternative_route_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    now: u64,
) -> Result<AlternativeRoute, Error> {
    let (attempt_id, binding) = alternative_identity(task, alternative)?;
    let resolution = reconcile_connector_intent_in_txn(
        vault, wtxn, attempt_id, &binding, None, now,
    )
    .map_err(|_| Error::InvariantViolation("ambient alternative frozen ledger binding mismatch"))?;
    let route = match resolution {
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
    };
    if !matches!(route, AlternativeRoute::Live | AlternativeRoute::Open) {
        return Ok(route);
    }
    let interrupt_ref = connector_logical_send_intent_ref(task);
    let interrupt_attempt =
        super::super::dispatch_attempt_id::outbound_dispatch_attempt_id(&interrupt_ref)
            .map_err(|_| Error::InvariantViolation("invalid connector logical send ref"))?;
    let interrupt_binding = ConnectorIntentBinding {
        intent: &task.intent,
        actor_ref: task.actor_ref,
        actor_class: task.actor_class.gate_actor_class(),
        counterparty_ref: task.counterparty_ref.as_deref(),
        originating_session_ref: task.originating_session_ref.as_deref(),
        calendar_invite: task.calendar_invite.as_ref(),
    };
    let interrupt = reconcile_connector_intent_in_txn(
        vault,
        wtxn,
        interrupt_attempt,
        &interrupt_binding,
        None,
        now,
    )
    .map_err(|_| Error::InvariantViolation("connector TASK frozen ledger binding mismatch"))?;
    let unresolved = matches!(
        interrupt,
        Some(IntentResolution::Pending {
            delivery: UnconfirmedDelivery::Unresolved,
            ..
        })
    );
    Ok(match (route, unresolved) {
        (AlternativeRoute::Live, true) => AlternativeRoute::Uncertain,
        (AlternativeRoute::Open, true) => AlternativeRoute::InterruptAlone,
        (route, _) => route,
    })
}

/// Sends a live alternative again: the TASK completes when it goes, waits on
/// its edge when it is held, settles a failure as the interrupt's own would
/// be, and is tried again otherwise, its own row deciding the next attempt.
fn send_live_alternative<S: OutboundExecutionSink>(
    vault: &Vault,
    sink: &mut S,
    queue: &AttemptQueue<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    request: &OutboundDispatchRequest,
    alternative: &OutboundAmbientAlternative,
) -> Result<RoutedAttempt, ConnectorTaskExecutorError> {
    if let Some(deadline) = alternative_wait_past_deadline(vault, task, alternative)? {
        // The provider's wait outlasts the caller's deadline: the
        // alternative is not sent again, and the TASK stops as the
        // interrupt's own wait would (FIX 8818).
        stop_alternative_at_deadline(vault, attempt, task, request, alternative, deadline)?;
        return Ok(RoutedAttempt::Settled);
    }
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
    let child = match dispatched {
        Ok(child) => child,
        Err(
            OutboundDispatchError::InvalidBoundActor
            | OutboundDispatchError::ObsoleteAskConfirmation,
        ) => {
            // Its binding no longer stands: the alternative stops, and the
            // next attempt routes by the stop.
            stop_alternative(
                vault,
                task,
                alternative,
                IntentEscalationReason::BindingInvalid,
                now,
            )?;
            retry_connector_task_attempt(
                queue,
                attempt,
                now,
                "ambient_alternative_binding_invalid",
                None,
            )?;
            return Ok(RoutedAttempt::Settled);
        }
        Err(_) => {
            retry_connector_task_attempt(
                queue,
                attempt,
                now,
                "ambient_alternative_dispatch_uncertain",
                None,
            )?;
            return Ok(RoutedAttempt::Settled);
        }
    };
    // FIX 4747: the alternative goes under the interrupt's send executor
    // fence. Found moved before its transport call, nothing was sent; the
    // TASK stays the lease holder's, as an interrupt's own stand-down leaves
    // it.
    if send_executor_stood_down(&child) {
        stand_down_connector_task_attempt(vault, attempt, task, now)?;
        return Ok(RoutedAttempt::Settled);
    }
    let outcome = child.outcome;
    let parked = parked_on_child(child, request, task, alternative, now);
    match outcome {
        OutboundDispatchOutcome::DeliveredToChannel | OutboundDispatchOutcome::Deferred => {
            // Settled on what the alternative's row says in the settling
            // writer: an accepted remote task may have failed since.
            let receipt = parked.receipt;
            let route = vault.with_write_txn_grouped(|wtxn| {
                let route = alternative_route_in_txn(vault, wtxn, task, alternative, now)?;
                match route {
                    AlternativeRoute::Went => {
                        complete_degraded_connector_task_in_txn(
                            vault, wtxn, attempt, task, receipt, now,
                        )?;
                    }
                    AlternativeRoute::Uncertain => {
                        settle_ambiguous_alternative_task_in_txn(
                            vault, wtxn, attempt, task, receipt, now,
                        )?;
                    }
                    AlternativeRoute::Open
                    | AlternativeRoute::InterruptAlone
                    | AlternativeRoute::Live => {}
                }
                Ok(route)
            })?;
            match route {
                AlternativeRoute::Went => Ok(RoutedAttempt::Went),
                AlternativeRoute::Uncertain => Ok(RoutedAttempt::Settled),
                AlternativeRoute::Open
                | AlternativeRoute::InterruptAlone
                | AlternativeRoute::Live => {
                    retry_connector_task_attempt(
                        queue,
                        attempt,
                        now,
                        "ambient_alternative_unsettled",
                        None,
                    )?;
                    Ok(RoutedAttempt::Settled)
                }
            }
        }
        OutboundDispatchOutcome::Held | OutboundDispatchOutcome::Degraded => {
            settle_held_connector_task(vault, queue, attempt, task.task_ref, task, parked, now)?;
            Ok(RoutedAttempt::Settled)
        }
        OutboundDispatchOutcome::Failed | OutboundDispatchOutcome::Ambiguous
            if !matches!(parked.resolution, Some(IntentResolution::Stopped { .. })) =>
        {
            let receipt_id = parked.receipt.receipt_id.clone();
            settle_failed_connector_task(
                vault,
                queue,
                attempt,
                task.task_ref,
                task,
                &receipt_id,
                parked,
                now,
            )?;
            Ok(RoutedAttempt::Settled)
        }
        OutboundDispatchOutcome::Suppressed | OutboundDispatchOutcome::LetGo => {
            if parked.receipt.fields.get("suppression").map(String::as_str) == Some("dedupe") {
                // The common door recorded the semantic dedupe: the TASK
                // settles as the interrupt's would.
                settle_suppressed_send(vault, attempt, task.task_ref, now)?;
                return Ok(RoutedAttempt::Settled);
            }
            // The Gate refuses the alternative now: it stops, so the next
            // attempt routes by the stop instead of asking again.
            let stop =
                if parked.gate_reason_codes.iter().any(|code| {
                    code == crate::gate::GateReasonCode::DenyConnectorKeySuspended.as_str()
                }) {
                    IntentEscalationReason::ConnectorRevoked
                } else {
                    IntentEscalationReason::BindingInvalid
                };
            stop_alternative(vault, task, alternative, stop, now)?;
            let reason = format!("ambient_alternative_{}", outcome.as_str());
            retry_connector_task_attempt(queue, attempt, now, &reason, None)?;
            Ok(RoutedAttempt::Settled)
        }
        _ => {
            // A stopped alternative: the next attempt routes by what its row
            // now says.
            let reason = format!("ambient_alternative_{}", outcome.as_str());
            retry_connector_task_attempt(
                queue,
                attempt,
                now,
                &reason,
                receipt_provider_retry_after(&parked.receipt),
            )?;
            Ok(RoutedAttempt::Settled)
        }
    }
}

/// The TASK's deadline, when the provider wait its alternative's row keeps
/// ends after it.
fn alternative_wait_past_deadline(
    vault: &Vault,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
) -> Result<Option<u64>, ConnectorTaskExecutorError> {
    let Some(deadline) = task.deadline_at else {
        return Ok(None);
    };
    let (attempt_id, _) = alternative_identity(task, alternative)?;
    let record = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(vault, &rtxn, attempt_id, 0)
            .map_err(OutboundDispatchError::from)?
    };
    let Some(record) = record else {
        return Ok(None);
    };
    let wait = crate::outbound_intent_ledger::intent_settlement(vault, &record.id)
        .map_err(OutboundDispatchError::from)?
        .provider_wait;
    Ok(wait
        .and_then(|wait| wait.not_before)
        .filter(|edge| *edge > deadline)
        .map(|_| deadline))
}

/// Ends the TASK at its deadline before its alternative goes again: the
/// interrupt's receipt names the alternative and the deadline, and the TASK
/// fails as not delivered.
fn stop_alternative_at_deadline(
    vault: &Vault,
    attempt: &crate::attempt_queue::AttemptRecord,
    task: &ConnectorSendTask,
    request: &OutboundDispatchRequest,
    alternative: &OutboundAmbientAlternative,
    deadline: u64,
) -> Result<(), ConnectorTaskExecutorError> {
    let now = vault.now_recorded_at();
    let failed = OutboundDispatchOutcome::Failed.as_str();
    let mut receipt = interrupt_receipt(request, task, alternative, failed, None, now);
    receipt
        .fields
        .insert("dispatch_outcome".to_owned(), failed.to_owned());
    receipt.fields.insert(
        PROVIDER_WAIT_DEADLINE_FIELD.to_owned(),
        deadline.to_string(),
    );
    crate::outbound::retry_audit::persist_terminal_send_receipt_and_fail(
        vault,
        crate::outbound::retry_audit::TerminalSendSettlement {
            attempt,
            task_ref: task.task_ref,
            receipt,
            receipt_outcome: SendReceiptOutcome::Failed,
            transport_dispatched: false,
            task_outcome: ConnectorSendTaskOutcome::Failed,
            reason: PROVIDER_WAIT_DEADLINE_REASON,
            now,
        },
    )?;
    Ok(())
}

/// Stops the alternative's admitted call with `stop`, in a writer of its own.
fn stop_alternative(
    vault: &Vault,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    stop: IntentEscalationReason,
    now: u64,
) -> Result<(), Error> {
    let (attempt_id, binding) = alternative_identity(task, alternative)?;
    vault.with_write_txn_grouped(|wtxn| {
        reconcile_connector_intent_in_txn(vault, wtxn, attempt_id, &binding, Some(stop), now)
            .map(drop)
            .map_err(|_| {
                Error::InvariantViolation("ambient alternative frozen ledger binding mismatch")
            })
    })
}

/// The alternative's dispatch result as the interrupt's: its outcome,
/// resolution and gate facts, under the interrupt's degraded receipt, which
/// names the alternative and its receipt and carries its retry edge and
/// delivery evidence.
fn parked_on_child(
    child: OutboundDispatchResult,
    request: &OutboundDispatchRequest,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    now: u64,
) -> OutboundDispatchResult {
    let mut receipt = interrupt_receipt(
        request,
        task,
        alternative,
        child.outcome.as_str(),
        Some(&child.receipt.receipt_id),
        now,
    );
    for field in CARRIED_CHILD_FIELDS {
        if let Some(value) = child.receipt.fields.get(field) {
            receipt.fields.insert(field.to_owned(), value.clone());
        }
    }
    let mut parked = child;
    parked.receipt = receipt;
    parked
}

/// The interrupt's receipt for an attempt its alternative carried: degraded,
/// naming the alternative, its receipt when known, and what came of it.
fn interrupt_receipt(
    request: &OutboundDispatchRequest,
    task: &ConnectorSendTask,
    alternative: &OutboundAmbientAlternative,
    outcome: &str,
    child_receipt: Option<&str>,
    now: u64,
) -> crate::receipt::ReceiptRecord {
    let mut receipt = crate::receipt::outbound_intent_receipt(
        request.receipt_id.clone(),
        request.intent_ref.clone(),
        &task.intent,
        now,
        OutboundDispatchOutcome::Degraded.as_str(),
    );
    name_ambient_alternative(&mut receipt, request, alternative, outcome, child_receipt);
    // The alternative's ledger row, by the identity it derives from the
    // TASK's logical send: named even when its receipt is not at hand.
    receipt.fields.insert(
        ALTERNATIVE_LEDGER_REF_FIELD.to_owned(),
        ambient_alternative_ref(
            &connector_logical_send_intent_ref(task),
            &alternative.surface,
        ),
    );
    receipt
}
