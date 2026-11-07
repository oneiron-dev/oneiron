//! Chokepoint OutboundTransport adapter: frozen-call guard, header/invite rehydration, sink execute.
use super::retry_after::{PROVIDER_RETRY_AFTER_FIELD, provider_retry_after_secs};
use crate::Vault;
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::connector_task::{
    SEND_EXECUTOR_FENCE_FIELD, SEND_EXECUTOR_STOOD_DOWN, send_executor_fence_permits_send,
};
use crate::outbound::dispatch_types::{
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionOutcomeKind,
    OutboundExecutionRequest, OutboundExecutionSink,
};
pub(super) struct DispatchChokepointTransport<'a, S> {
    vault: &'a Vault,
    request: &'a OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
    sink: &'a mut S,
    pub(super) execution: Option<OutboundExecutionOutcome>,
}
impl<'a, S> DispatchChokepointTransport<'a, S> {
    pub(super) fn new(
        vault: &'a Vault,
        request: &'a OutboundDispatchRequest,
        verb_contract: &'static OutboundVerbContract,
        sink: &'a mut S,
    ) -> Self {
        Self {
            vault,
            request,
            verb_contract,
            sink,
            execution: None,
        }
    }
}
impl<S: OutboundExecutionSink> crate::outbound_chokepoint::OutboundTransport
    for DispatchChokepointTransport<'_, S>
{
    fn send(
        &mut self,
        call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> crate::outbound_intent_ledger::OutboundSendOutcome {
        let vault = self.vault;
        let fence = self.request.send_executor_fence.as_ref();
        let sink = &mut *self.sink;
        let Some(dispatched) = with_execution_request(
            vault,
            self.request,
            self.verb_contract,
            call,
            |execution_request| {
                // FIX 4747, the fence before the bytes: a connector-send
                // TASK's send goes only while this machine still holds the
                // exact send executor lease its attempt took. A stale
                // executor stands down here, at the last point every send
                // kind passes, and its sink is never called.
                if let Some(fence) = fence
                    && !send_executor_fence_permits_send(vault, fence)
                {
                    return None;
                }
                Some(sink.execute(execution_request))
            },
        ) else {
            return invalid_frozen_call();
        };
        let Some(mut execution) = dispatched else {
            self.execution = Some(
                OutboundExecutionOutcome::failed(SEND_EXECUTOR_STOOD_DOWN)
                    .with_receipt_field(SEND_EXECUTOR_FENCE_FIELD, SEND_EXECUTOR_STOOD_DOWN),
            );
            return transport_not_started();
        };
        // Only the pipeline may author the normalized re-arm authority, even
        // when the adapter's raw `retry_after` is missing or malformed.
        execution.receipt_fields.remove(PROVIDER_RETRY_AFTER_FIELD);
        let outcome = match execution.kind {
            OutboundExecutionOutcomeKind::DeliveredToChannel => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Acked
            }
            OutboundExecutionOutcomeKind::Deferred => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Deferred
            }
            OutboundExecutionOutcomeKind::Failed if execution.delivery_may_have_occurred => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Ambiguous
            }
            OutboundExecutionOutcomeKind::Failed => transport_not_started(),
        };
        self.execution = Some(execution);
        outcome
    }

    fn remote_task(&self) -> Option<crate::outbound_intent_ledger::RemoteTaskHandle> {
        self.execution
            .as_ref()
            .filter(|execution| execution.kind == OutboundExecutionOutcomeKind::Deferred)
            .and_then(|execution| execution.remote_task.clone())
    }

    /// A definite non-delivery the sink marked as its provider's rate or
    /// quota refusal, with the seconds that provider stated (FIX 8818).
    fn provider_wait(&self) -> Option<crate::outbound_intent_ledger::ProviderWait> {
        let execution = self.execution.as_ref().filter(|execution| {
            execution.kind == OutboundExecutionOutcomeKind::Failed
                && !execution.delivery_may_have_occurred
        })?;
        Some(crate::outbound_intent_ledger::ProviderWait {
            kind: execution.provider_wait?,
            retry_after_secs: provider_retry_after_secs(execution),
        })
    }

    /// The pipeline holds a paced send and names its `retry_at`, which the
    /// connector task executor re-arms at (FIX 8686).
    fn waits_for_paced_window(&self) -> bool {
        true
    }

    fn admit_in(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<(), crate::outbound_intent_ledger::IntentLedgerError> {
        self.sink
            .admit_in(txn)
            .map_err(crate::outbound_intent_ledger::IntentLedgerError::from)
    }

    /// The sink's proof of non-delivery, for a call this transport would
    /// send (FIX 9379).
    fn known_non_delivery(&self, call: &crate::outbound_intent_ledger::FrozenOutboundCall) -> bool {
        call.server() == self.request.intent.channel
            && call.tool() == self.verb_contract.kind
            && call.resolved_endpoint().is_none()
            && self
                .sink
                .known_non_delivery(&self.request.intent_ref, call.idempotency_key())
    }

    /// The sink's read-back of `call`, for a call this transport would send,
    /// through the request it would execute (FIX 8814 follow-up).
    fn read_back_delivery(
        &self,
        call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> crate::outbound_intent_ledger::DeliveryReadBack {
        let sink = &*self.sink;
        with_execution_request(
            self.vault,
            self.request,
            self.verb_contract,
            call,
            |execution_request| sink.read_back_delivery(execution_request),
        )
        .unwrap_or(crate::outbound_intent_ledger::DeliveryReadBack::Unknown)
    }
}

/// Builds the request the sink gets for `call`, the frozen call the
/// transport would send, and hands it to `with`: `None` for a call it would
/// refuse. The send and its read-back (FIX 8814 follow-up) both build it
/// here, so a sink reads back exactly the call it executed.
fn with_execution_request<R>(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
    call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    with: impl FnOnce(&OutboundExecutionRequest<'_>) -> R,
) -> Option<R> {
    if call.server() != request.intent.channel
        || call.tool() != verb_contract.kind
        || call.resolved_endpoint().is_some()
    {
        return None;
    }
    // The last in-process boundary before the connector: the hygiene
    // headers come out of the frozen bytes, never out of the live request.
    let Ok(hygiene_headers) = crate::outbound_chokepoint::frozen_call_hygiene_headers(call) else {
        return None;
    };
    // CAL-04, same discipline: a `calendar.invite` send resolves its
    // `text/calendar` part from the FROZEN blob ref here, at the last
    // in-process boundary, and never recomputes a UID, a SEQUENCE, or the
    // document itself. A verb-registered invite whose frozen bytes carry no
    // five-field body — or whose blob ref no longer dereferences — fails
    // closed rather than going out as a plain email about a meeting.
    let calendar_invite = if verb_contract.kind == crate::calendar::CALENDAR_INVITE_VERB {
        let Ok(payload) = crate::calendar::decode_frozen_calendar_invite(call.payload()) else {
            return None;
        };
        let Ok(part) = crate::calendar::build_calendar_invite_mime_part(vault, &payload) else {
            return None;
        };
        Some(part)
    } else {
        None
    };
    let Ok(space_posting) = crate::channel_identity_autonomy::frozen_space_posting(call.payload())
    else {
        return None;
    };
    // FIX 8791: the sink's own profile-read hold waits for the seat's
    // daily reset, named on the request's clock.
    let linkedin_sandbox_policy = request
        .linkedin_sandbox_policy
        .clone()
        .map(|policy| policy.with_caps_reset_after(request.occurred_at));
    let execution_request = OutboundExecutionRequest {
        intent_ref: &request.intent_ref,
        intent: &request.intent,
        // Only provider-native and replace-safe verbs expose the frozen
        // ledger key to the transport. Queue-emulated dedupe does not make
        // an ambiguous provider call safe to resend.
        idempotency_key: if call.idempotency_supported() {
            call.idempotency_key()
        } else {
            None
        },
        verb_contract,
        channel_identity_ref: request.channel_identity_ref,
        counterparty_ref: request.counterparty_ref.as_deref(),
        linkedin_sandbox_policy: linkedin_sandbox_policy.as_ref(),
        hygiene_headers,
        apns_interruption_level: request.delivery_window_apns_interruption_level,
        calendar_invite,
        space_posting,
    };
    if !crate::task_verb::validate_ask_soft_confirm_dispatch(vault, request).unwrap_or(false) {
        return None;
    }
    Some(with(&execution_request))
}

/// A definite non-delivery: no byte of this call left for its provider.
fn transport_not_started() -> crate::outbound_intent_ledger::OutboundSendOutcome {
    crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
        crate::outbound_intent_ledger::OutboundSendFailure {
            kind: crate::outbound_intent_ledger::OutboundFailureKind::TransportNotStarted,
            code: None,
            secret: None,
        },
    )
}
/// A frozen call the dispatch transport cannot honor verbatim.
fn invalid_frozen_call() -> crate::outbound_intent_ledger::OutboundSendOutcome {
    crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
        crate::outbound_intent_ledger::OutboundSendFailure {
            kind: crate::outbound_intent_ledger::OutboundFailureKind::InvalidRequest,
            code: None,
            secret: None,
        },
    )
}
