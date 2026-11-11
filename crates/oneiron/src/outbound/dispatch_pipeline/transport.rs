//! Chokepoint OutboundTransport adapter: frozen-call guard, header/invite rehydration, sink execute.
use super::retry_after::{PROVIDER_RETRY_AFTER_FIELD, provider_retry_after_secs};
use crate::Vault;
use crate::agent_dispatch::{AGENT_RUN_FENCE_FIELD, AGENT_RUN_STOOD_DOWN};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::connector_task::{
    SEND_EXECUTOR_FENCE_FIELD, SEND_EXECUTOR_STOOD_DOWN, send_executor_fence_permits_send,
};
use crate::outbound::dispatch_types::{
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionOutcomeKind,
    OutboundExecutionRequest, OutboundExecutionSink,
};
use crate::outbound::send_lookup::{
    SENT_LOOKUP_CANNOT_TELL, SENT_LOOKUP_CANNOT_TELL_REASON, SENT_LOOKUP_DEDUPED_RESEND,
    SENT_LOOKUP_FIELD, SENT_LOOKUP_NOT_SENT, SENT_LOOKUP_SENT,
};
use crate::outbound::{SentLookup, SentLookupTarget};
use crate::outbound_chokepoint::UncertainSendStep;
pub(super) struct DispatchChokepointTransport<'a, S> {
    vault: &'a Vault,
    request: &'a OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
    sink: &'a mut S,
    pub(super) execution: Option<OutboundExecutionOutcome>,
    /// FIX 4747: what this dispatch's one provider lookup found, once it
    /// ran; a dispatch looks its send up at most once.
    looked_up: Option<LookupFound>,
}

/// What a dispatch's provider lookup found (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupFound {
    Sent,
    NotSent,
    DedupedResend,
    CannotTell,
}

/// What a dispatch's one sink call did: it executed the send, or the
/// provider lookup before it (FIX 4747) settled the send, with nothing sent
/// now, as the execution and outcome it stands for.
enum SinkCall {
    Executed(OutboundExecutionOutcome),
    /// FIX 4747 slice 5: the agent run that started this send is no longer
    /// held by this machine; nothing was sent.
    RunStoodDown,
    LookedUp(
        OutboundExecutionOutcome,
        crate::outbound_intent_ledger::OutboundSendOutcome,
    ),
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
            looked_up: None,
        }
    }
}

/// What a lookup of `request`'s send may read: its frozen intent, its verb
/// and the sender identity the dispatch resolved (FIX 4747).
fn sent_lookup_target<'r>(
    request: &'r OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
) -> SentLookupTarget<'r> {
    SentLookupTarget {
        intent_ref: &request.intent_ref,
        intent: &request.intent,
        verb_contract,
        channel_identity_ref: request.channel_identity_ref,
        send_approved_at: request.send_approved_at,
    }
}

/// The execution a lookup that found the send kept stands for: delivered
/// under the provider's ref, with nothing sent now (FIX 4747).
fn looked_up_sent(provider_ref: String) -> OutboundExecutionOutcome {
    OutboundExecutionOutcome::delivered_to_channel(provider_ref)
        .with_receipt_field(SENT_LOOKUP_FIELD, SENT_LOOKUP_SENT)
}

/// The execution a lookup that could not tell stands for: nothing sent now,
/// and an earlier send may have gone (FIX 4747).
fn looked_up_cannot_tell() -> OutboundExecutionOutcome {
    OutboundExecutionOutcome::failed(SENT_LOOKUP_CANNOT_TELL_REASON)
        .with_possible_delivery()
        .with_receipt_field(SENT_LOOKUP_FIELD, SENT_LOOKUP_CANNOT_TELL)
}

impl<S: OutboundExecutionSink> DispatchChokepointTransport<'_, S> {
    /// Whether the sink delivers this send whole (fix list row 17645): a
    /// message to several recipients goes only through a sink that sends it
    /// to every one of them, never to its first alone.
    fn sink_delivers_every_recipient(&self) -> bool {
        self.request.intent.recipients.is_empty() || self.sink.delivers_recipient_lists()
    }
}

impl<S: OutboundExecutionSink> crate::outbound_chokepoint::OutboundTransport
    for DispatchChokepointTransport<'_, S>
{
    fn send(
        &mut self,
        call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> crate::outbound_intent_ledger::OutboundSendOutcome {
        // A message to several recipients goes only through a sink that
        // sends it to every one of them, never to its first alone (fix list
        // row 17645).
        if !self.sink_delivers_every_recipient() {
            return invalid_frozen_call();
        }
        let vault = self.vault;
        let request = self.request;
        let verb_contract = self.verb_contract;
        let fence = request.send_executor_fence.as_ref();
        let sink = &mut *self.sink;
        let looked_up = &mut self.looked_up;
        let Some(dispatched) =
            with_execution_request(vault, request, verb_contract, call, |execution_request| {
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
                // FIX 4747 slice 5: a send an agent run starts goes only
                // while that run's machine still holds the run; a stale
                // executor stands down here, at the same last point, and its
                // sink is never called.
                if let Some(run_fence) = request.agent_run_fence.as_ref()
                    && !crate::agent_dispatch::agent_run_fence_permits_effect(vault, run_fence)
                {
                    return Some(SinkCall::RunStoodDown);
                }
                // FIX 4747: a send an earlier executor of its TASK may have
                // made is looked up first: one the provider kept settles
                // delivered, sending nothing; one nobody can tell about
                // sends nothing and stays uncertain for the owner's ask;
                // only one the provider has not seen goes. The owner's
                // resend goes with no lookup.
                if request.earlier_send_lookup
                    && !request.owner_released_resend
                    && looked_up.is_none()
                    && let Some(engine_send_id) = request.engine_send_id.as_ref()
                {
                    let target = sent_lookup_target(request, verb_contract);
                    match sink.lookup_sent(engine_send_id, &target) {
                        SentLookup::Sent { provider_ref } => {
                            *looked_up = Some(LookupFound::Sent);
                            return Some(SinkCall::LookedUp(
                                looked_up_sent(provider_ref),
                                crate::outbound_intent_ledger::OutboundSendOutcome::Acked,
                            ));
                        }
                        SentLookup::NotSent => *looked_up = Some(LookupFound::NotSent),
                        SentLookup::DedupedResend => {
                            *looked_up = Some(LookupFound::DedupedResend);
                        }
                        SentLookup::CannotTell => {
                            *looked_up = Some(LookupFound::CannotTell);
                            return Some(SinkCall::LookedUp(
                                looked_up_cannot_tell(),
                                crate::outbound_intent_ledger::OutboundSendOutcome::Ambiguous,
                            ));
                        }
                    }
                }
                Some(SinkCall::Executed(sink.execute(execution_request)))
            })
        else {
            return invalid_frozen_call();
        };
        let mut execution = match dispatched {
            Some(SinkCall::Executed(execution)) => execution,
            Some(SinkCall::LookedUp(execution, outcome)) => {
                self.execution = Some(execution);
                return outcome;
            }
            Some(SinkCall::RunStoodDown) => {
                self.execution = Some(
                    OutboundExecutionOutcome::failed(AGENT_RUN_STOOD_DOWN)
                        .with_receipt_field(AGENT_RUN_FENCE_FIELD, AGENT_RUN_STOOD_DOWN),
                );
                return transport_not_started();
            }
            None => {
                self.execution = Some(
                    OutboundExecutionOutcome::failed(SEND_EXECUTOR_STOOD_DOWN)
                        .with_receipt_field(SEND_EXECUTOR_FENCE_FIELD, SEND_EXECUTOR_STOOD_DOWN),
                );
                return transport_not_started();
            }
        };
        let looked_up_field = match self.looked_up {
            Some(LookupFound::NotSent) => Some(SENT_LOOKUP_NOT_SENT),
            Some(LookupFound::DedupedResend) => Some(SENT_LOOKUP_DEDUPED_RESEND),
            _ => None,
        };
        if let Some(found) = looked_up_field {
            execution
                .receipt_fields
                .insert(SENT_LOOKUP_FIELD.to_owned(), found.to_owned());
        }
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
        if !self.sink_delivers_every_recipient() {
            return Err(
                crate::outbound_intent_ledger::IntentLedgerError::InvalidInput(
                    "the sink sends to one recipient, and the message names several",
                ),
            );
        }
        self.sink
            .admit_in(txn)
            .map_err(crate::outbound_intent_ledger::IntentLedgerError::from)
    }

    /// A connector-send TASK's dispatch looks a send that may have gone out
    /// up before any resend (FIX 4747).
    fn looks_up_uncertain_sends(&self) -> bool {
        self.request.engine_send_id.is_some()
    }

    /// A LINE push or narrowcast of a connector-send TASK: LINE keeps its
    /// retry key for 24 hours only (FIX 4747, review #6555). Engine call
    /// (CALLS, FIX 4747): the channels and verbs whose key lapses.
    fn idempotent_resend_is_time_bounded(
        &self,
        _call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> bool {
        self.request.engine_send_id.is_some()
            && crate::outbound::capability::normalize_key(&self.request.intent.channel)
                == crate::channel_identity_provider::LINE_CHANNEL
            && matches!(self.request.intent.verb.as_str(), "push" | "narrowcast")
    }

    /// The owner's resend releases the uncertain call; else the sink's
    /// provider lookup for a call this transport would send decides (FIX
    /// 4747). A call this transport would not send, or a second lookup in
    /// one dispatch, holds.
    fn uncertain_send_step(
        &mut self,
        call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> UncertainSendStep {
        let request = self.request;
        let Some(engine_send_id) = request.engine_send_id.as_ref() else {
            return UncertainSendStep::Hold;
        };
        if call.server() != request.intent.channel
            || call.tool() != self.verb_contract.kind
            || call.resolved_endpoint().is_some()
        {
            self.execution = Some(looked_up_cannot_tell());
            return UncertainSendStep::Hold;
        }
        if request.owner_released_resend {
            return UncertainSendStep::OwnerReleased;
        }
        if self.looked_up.is_some() {
            self.execution = Some(looked_up_cannot_tell());
            return UncertainSendStep::Hold;
        }
        let target = sent_lookup_target(request, self.verb_contract);
        match self.sink.lookup_sent(engine_send_id, &target) {
            SentLookup::Sent { provider_ref } => {
                self.looked_up = Some(LookupFound::Sent);
                self.execution = Some(looked_up_sent(provider_ref));
                UncertainSendStep::Delivered
            }
            SentLookup::NotSent => {
                self.looked_up = Some(LookupFound::NotSent);
                UncertainSendStep::LookedUpUnsent
            }
            SentLookup::DedupedResend => {
                self.looked_up = Some(LookupFound::DedupedResend);
                UncertainSendStep::ResendDeduplicated
            }
            SentLookup::CannotTell => {
                self.looked_up = Some(LookupFound::CannotTell);
                self.execution = Some(looked_up_cannot_tell());
                UncertainSendStep::Hold
            }
        }
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
        engine_send_id: request.engine_send_id.as_ref(),
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
