//! Chokepoint OutboundTransport adapter: frozen-call guard, header/invite rehydration, sink execute.
use super::retry_after::PROVIDER_RETRY_AFTER_FIELD;
use crate::Vault;
use crate::outbound::capability::OutboundVerbContract;
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
        if call.server() != self.request.intent.channel
            || call.tool() != self.verb_contract.kind
            || call.resolved_endpoint().is_some()
        {
            return invalid_frozen_call();
        }
        // The last in-process boundary before the connector: the hygiene
        // headers come out of the frozen bytes, never out of the live request.
        let Ok(hygiene_headers) = crate::outbound_chokepoint::frozen_call_hygiene_headers(call)
        else {
            return invalid_frozen_call();
        };
        // CAL-04, same discipline: a `calendar.invite` send resolves its
        // `text/calendar` part from the FROZEN blob ref here, at the last
        // in-process boundary, and never recomputes a UID, a SEQUENCE, or the
        // document itself. A verb-registered invite whose frozen bytes carry no
        // five-field body — or whose blob ref no longer dereferences — fails
        // closed rather than going out as a plain email about a meeting.
        let calendar_invite = if self.verb_contract.kind == crate::calendar::CALENDAR_INVITE_VERB {
            let Ok(payload) = crate::calendar::decode_frozen_calendar_invite(call.payload()) else {
                return invalid_frozen_call();
            };
            let Ok(part) = crate::calendar::build_calendar_invite_mime_part(self.vault, &payload)
            else {
                return invalid_frozen_call();
            };
            Some(part)
        } else {
            None
        };
        let execution_request = OutboundExecutionRequest {
            intent_ref: &self.request.intent_ref,
            intent: &self.request.intent,
            // The ledger id doubles as the frozen call's idempotency key, but a
            // sink must only be told it has provider idempotency when the verb
            // actually supports it. A non-idempotent send exposes no key, so the
            // transport cannot mistake the ledger id for a dedupe token.
            idempotency_key: if call.idempotency_supported() {
                call.idempotency_key()
            } else {
                None
            },
            verb_contract: self.verb_contract,
            channel_identity_ref: self.request.channel_identity_ref,
            counterparty_ref: self.request.counterparty_ref.as_deref(),
            hygiene_headers,
            apns_interruption_level: self.request.delivery_window_apns_interruption_level,
            calendar_invite,
        };
        let mut execution = self.sink.execute(&execution_request);
        // Only the pipeline may author the normalized re-arm authority, even
        // when the adapter's raw `retry_after` is missing or malformed.
        execution.receipt_fields.remove(PROVIDER_RETRY_AFTER_FIELD);
        let outcome = match execution.kind {
            OutboundExecutionOutcomeKind::DeliveredToChannel => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Acked
            }
            OutboundExecutionOutcomeKind::Failed if execution.delivery_may_have_occurred => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Ambiguous
            }
            OutboundExecutionOutcomeKind::Failed => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
                    crate::outbound_intent_ledger::OutboundSendFailure {
                        kind:
                            crate::outbound_intent_ledger::OutboundFailureKind::TransportNotStarted,
                        code: None,
                    },
                )
            }
        };
        self.execution = Some(execution);
        outcome
    }
}
/// A frozen call the dispatch transport cannot honor verbatim.
fn invalid_frozen_call() -> crate::outbound_intent_ledger::OutboundSendOutcome {
    crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
        crate::outbound_intent_ledger::OutboundSendFailure {
            kind: crate::outbound_intent_ledger::OutboundFailureKind::InvalidRequest,
            code: None,
        },
    )
}
