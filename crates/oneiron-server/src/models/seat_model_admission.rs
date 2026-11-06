//! A seat's paid model calls on the model door (FIX 15702 slice 3; Engine
//! call 14:12, A, mirroring the AI host's step): one run admission per seat
//! claim, on the vault's budget policy for the claim's own agent, bounded by
//! the attempt's spend scope read live when it has one. Each request the
//! door sends is admitted on that run for the exact bytes it sends, through
//! the offer the slot's provider binds for the model it names, before the
//! key is read; its permit starts after the key is read and before the
//! broker sends; it settles once, on its answer's reported usage, on its
//! reservation when the answer reports none, or as failed. Its spend lands
//! on the vault's usage ledger through the run's receipts, and on the
//! attempt's spend scope as it settles.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::dispatch_byoa::ByoaExecutionFence;
use oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
use oneiron::llm::run_admission::{
    CallOutcome, OfferBinding, RawDispatch, RunAdmission, RunCall, RunDenied, RunPermit,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, EdgeActorClass,
    EntityId, LlmRequest, LlmResult, LlmUsage, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    WriteActor,
};
use oneiron_llm_anthropic::parse_anthropic_usage;
use oneiron_llm_openai::parse_openai_usage;
use serde_json::Value as JsonValue;

use super::ModelRuntime;
use super::seat_model::SeatModelRefusal;
use super::sse::{SseDecoder, SseEvent};
use crate::ai_host::live_lease::{LiveLease, LiveLeaseState};
use crate::ai_host::payer_funding::{requires_payer, scope_funding};
use crate::runtime::SeatModelProtocol;
use crate::server::SyncServer;

/// The purpose a seat's model calls are admitted under.
const SEAT_MODEL_PURPOSE: &str = "seat.model";

/// One seat claim's paid model calls: its run and its spend scope's lease.
pub(crate) struct SeatModelMeter {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    run_id: String,
    guard: BudgetGuard,
    /// The claim's own agent, every call's initiator.
    holder: EntityId,
    scope: Option<SpendScopeId>,
    payer_required: bool,
    lease: LiveLeaseState,
    /// The claim's run, built once its spend scope's payer resolves. Until
    /// then its payer is read again at each call, which is refused while it
    /// cannot be read or holds on the owners' payer-needed ask, never billed
    /// to the vault owner.
    run: OnceLock<RunAdmission>,
}

impl SeatModelMeter {
    /// The meter of `fence`'s claim, its calls the claim's own agent
    /// `holder`'s: the vault's budget policy for that agent, bounded by
    /// what the attempt's spend scope has left when it has one, and billed
    /// to the payer that scope's root names (OF-531), as the AI host's step
    /// is. A scope whose payer this host cannot bill yet queues the owners'
    /// payer-needed ask, and the claim's calls are refused meanwhile.
    ///
    /// # Errors
    ///
    /// Reading the spend scope, or the policy manifest, which fails closed.
    pub(crate) fn open(
        server: &SyncServer,
        fence: &ByoaExecutionFence,
        holder: EntityId,
    ) -> oneiron::Result<Arc<Self>> {
        let vault = Arc::clone(server.vault());
        let dispatcher = AgentDispatcher::new(&vault);
        let scope = dispatcher.spend_scope_for_attempt(fence.attempt_id)?;
        let limit = match &scope {
            Some(scope) => dispatcher.available_units(scope)?,
            None => u64::MAX,
        };
        let attempt = *fence.attempt_id.as_bytes();
        let actor = WriteActor::new(holder, EdgeActorClass::Agent).with_run_attempt(attempt);
        let run_id = format!(
            "seat-model/{}/{}",
            EntityId::from_bytes_unchecked(attempt).to_hex(),
            fence.attempt_count
        );
        let meter = vault.policy_budget_guard(
            run_id.clone(),
            limit,
            DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            actor,
        )?;
        let payer_required = requires_payer(&vault, fence.attempt_id, false)?;
        let lease = LiveLease::new(&vault, scope.clone(), meter.clone(), limit, 0).state();
        let claim = Arc::new(Self {
            vault,
            models: Arc::clone(server.ai.models()),
            run_id,
            guard: meter,
            holder,
            scope,
            payer_required,
            lease,
            run: OnceLock::new(),
        });
        // Reading the payer now queues the owners' payer-needed ask as the
        // claim opens, not at its first call.
        let _ = claim.funded();
        Ok(claim)
    }

    /// The claim's run, its payer read first while it has none: the payer
    /// the spend scope's root names (OF-531), every permit initiated by the
    /// claim's own agent, so a host-paid call draws on that resident's
    /// pinned share and settles on it.
    ///
    /// # Errors
    ///
    /// [`SeatModelRefusal::Unfunded`] while the payer cannot be read or
    /// holds on the owners' payer-needed ask.
    fn funded(&self) -> Result<&RunAdmission, SeatModelRefusal> {
        if let Some(run) = self.run.get() {
            return Ok(run);
        }
        match scope_funding(&self.vault, self.scope.as_ref(), self.payer_required) {
            Ok(payer) => Ok(self.run.get_or_init(|| {
                self.models
                    .funded_run(self.run_id.clone(), self.guard.clone(), payer)
                    .initiated_by(Some(self.holder))
            })),
            Err(fault) => {
                tracing::warn!(
                    reason = fault.reason(),
                    "a seat claim's model calls have no account to bill; they are refused"
                );
                Err(SeatModelRefusal::Unfunded(fault.reason()))
            }
        }
    }

    /// Books on the spend scope what the claim spent since the last look,
    /// and bounds the next admission by what the scope has left now.
    fn book(&self) {
        LiveLease::from_state(&self.vault, self.lease.clone()).book_and_revise();
    }

    /// Books what no look booked, once the claim ends.
    pub(crate) fn book_rest(&self) {
        if let Err(error) = LiveLease::from_state(&self.vault, self.lease.clone()).book_rest() {
            tracing::warn!(%error, "a seat claim's model spend was not booked on its scope");
        }
    }

    /// Refuses a request whose model no offer of its provider serves: one
    /// `Denied` row, nothing reserved; a claim with no account to bill is
    /// refused as unfunded.
    pub(crate) fn refuse_unoffered(&self, wire_model: &str) -> SeatModelRefusal {
        match self.funded() {
            Ok(run) => SeatModelRefusal::Denied(run.refuse(
                None,
                oneiron::llm::run_admission::UNRESOLVED_SELECTOR,
                RunDenied::UnknownSelector {
                    len: wire_model.len(),
                },
            )),
            Err(refusal) => refusal,
        }
    }

    /// Admits one request through `offer`, for the bytes whose digest is
    /// `digest`, before any key is read: the run's line, bounded by the
    /// scope's live room, and for a host-paid offer the vault's allocation.
    /// The call's guard settles it, whatever happens to it.
    ///
    /// # Errors
    ///
    /// The run's refusal, or no account to bill; nothing is reserved.
    pub(crate) fn admit(
        self: &Arc<Self>,
        offer: &OfferBinding,
        wire_model: &str,
        digest: &str,
        protocol: SeatModelProtocol,
    ) -> Result<SeatModelCall, SeatModelRefusal> {
        let run = self.funded()?;
        self.book();
        let request = admission_request(offer);
        let permit = run
            .admit_request(
                RunCall {
                    selector: Some(wire_model),
                    request: &request,
                    offer,
                },
                digest,
            )
            .map_err(SeatModelRefusal::Denied)?;
        let dispatch = run.raw_dispatch(&permit, offer, digest, None);
        Ok(SeatModelCall {
            meter: Arc::clone(self),
            permit: Some(permit),
            dispatch,
            usage: SeatModelUsage::new(protocol),
            success: false,
        })
    }
}

/// The model-free request a seat's call is admitted as: the offer's model,
/// at its route's locality, for the seat's purpose. It is never sent; the
/// provider gets the seat's own bytes.
fn admission_request(offer: &OfferBinding) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: SEAT_MODEL_PURPOSE.to_owned(),
    };
    LlmRequest {
        model: offer.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(offer.model.as_str().to_owned()),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: offer.locality,
            host_keyless: false,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// One admitted call of the seat's model door, from its permit to its
/// settlement: the permit starts at [`Self::start`], and the call settles
/// once, at its end, or as its guard drops. A call that never started pays
/// nothing; one that started and got no complete answer pays its
/// reservation.
pub(crate) struct SeatModelCall {
    meter: Arc<SeatModelMeter>,
    permit: Option<RunPermit>,
    dispatch: RawDispatch,
    usage: SeatModelUsage,
    /// The provider answered a success status.
    success: bool,
}

impl SeatModelCall {
    /// The permit's lease, which the broker's physical attempt counts on.
    pub(crate) fn lease(&self) -> Option<&oneiron::BudgetLease> {
        self.permit.as_ref().map(RunPermit::lease)
    }

    /// Starts the call's permit, after the key is read and before the
    /// broker sends.
    ///
    /// # Errors
    ///
    /// The run's refusal to start it: nothing is sent.
    pub(crate) fn start(&self) -> LlmResult<()> {
        self.dispatch.start()
    }

    /// Ends a buffered call on the provider's `status` and `body`: a
    /// success whose body is one JSON reply is answered, on the usage it
    /// reports.
    pub(crate) fn end_whole(mut self, status: u16, body: &[u8]) {
        self.success = (200..300).contains(&status);
        self.usage.whole(body);
        self.end();
    }

    /// The provider answered `status` to a streamed call.
    pub(crate) fn answered(&mut self, status: u16) {
        self.success = (200..300).contains(&status);
    }

    /// Reads one relayed chunk of a streamed reply, as it goes back.
    pub(crate) fn relayed(&mut self, chunk: &[u8]) {
        if self.success {
            self.usage.feed(chunk);
        }
    }

    /// Settles a streamed call whose reply ended cleanly: its last event,
    /// even without its blank line, still counts.
    pub(crate) fn end_stream(&mut self) {
        if self.success {
            self.usage.finish();
        }
        self.end();
    }

    /// Settles the call, once: answered on its reported usage when the
    /// provider's success reached its protocol's end, else failed.
    pub(crate) fn end(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let answered = self.success && self.usage.terminal;
        let served = self.usage.served.clone().filter(|_| answered);
        self.dispatch.finish(served, answered);
        let usage = self.usage.usage.take().unwrap_or_else(LlmUsage::zero);
        let settled = if answered {
            permit.settle(CallOutcome::Answered(&usage))
        } else {
            permit.settle(CallOutcome::Failed)
        };
        if let Err(denied) = settled {
            tracing::warn!(%denied, "a seat model call's settlement was refused");
        }
        self.meter.book();
    }
}

impl Drop for SeatModelCall {
    fn drop(&mut self) {
        self.end();
    }
}

/// What a relayed reply reports of its usage and its end, read from its
/// bytes as they go back, never changing them: an OpenAI chat `usage`
/// object and `[DONE]`, or Anthropic's `message_start`, `message_delta` and
/// `message_stop`. A streamed reply is read event by event through the
/// server-sent-events decoder, its data lines joined. No reply text is
/// kept past its event.
struct SeatModelUsage {
    protocol: SeatModelProtocol,
    usage: Option<LlmUsage>,
    /// The model the provider said it served.
    served: Option<String>,
    /// The reply reached its protocol's end.
    terminal: bool,
    events: SseDecoder,
    /// An event outgrew the decoder: the reply's usage is unknown from
    /// there, and the call pays its reservation.
    broken: bool,
}

impl SeatModelUsage {
    fn new(protocol: SeatModelProtocol) -> Self {
        Self {
            protocol,
            usage: None,
            served: None,
            terminal: false,
            events: SseDecoder::default(),
            broken: false,
        }
    }

    /// A whole reply: one JSON object is a complete answer.
    fn whole(&mut self, body: &[u8]) {
        let Ok(reply) = serde_json::from_slice::<JsonValue>(body) else {
            return;
        };
        if !reply.is_object() {
            return;
        }
        self.terminal = true;
        self.served = reply
            .get("model")
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        if let Some(usage) = reply.get("usage").filter(|usage| usage.is_object()) {
            self.usage = Some(self.parse(usage));
        }
    }

    fn parse(&self, usage: &JsonValue) -> LlmUsage {
        match self.protocol {
            SeatModelProtocol::OpenAiChat => parse_openai_usage(usage),
            SeatModelProtocol::AnthropicMessages => parse_anthropic_usage(usage),
        }
    }

    /// A streamed chunk: each event it completes is read once.
    fn feed(&mut self, chunk: &[u8]) {
        if self.broken {
            return;
        }
        match self.events.push(chunk) {
            Ok(events) => {
                for event in &events {
                    self.event(event);
                }
            }
            Err(_) => self.unknown(),
        }
    }

    /// The stream ended cleanly: a last event without its blank line counts.
    fn finish(&mut self) {
        if self.broken {
            return;
        }
        for event in &self.events.finish() {
            self.event(event);
        }
    }

    /// An event outgrew the decoder: nothing it or a later event reports is
    /// trusted, and the reply is never read as ended.
    fn unknown(&mut self) {
        self.broken = true;
        self.usage = None;
        self.terminal = false;
    }

    /// One event's joined data, when it can carry usage or the end.
    fn event(&mut self, event: &SseEvent) {
        let data = event.data.trim();
        match self.protocol {
            SeatModelProtocol::OpenAiChat => {
                if data == "[DONE]" {
                    self.terminal = true;
                    return;
                }
                if !data.contains("\"usage\"") {
                    return;
                }
                let Ok(event) = serde_json::from_str::<JsonValue>(data) else {
                    return;
                };
                if let Some(usage) = event.get("usage").filter(|usage| usage.is_object()) {
                    self.usage = Some(parse_openai_usage(usage));
                    self.served = event
                        .get("model")
                        .and_then(JsonValue::as_str)
                        .map(str::to_owned);
                }
            }
            SeatModelProtocol::AnthropicMessages => {
                if !data.contains("\"message_") {
                    return;
                }
                let Ok(event) = serde_json::from_str::<JsonValue>(data) else {
                    return;
                };
                match event.get("type").and_then(JsonValue::as_str) {
                    Some("message_start") => {
                        let message = &event["message"];
                        if let Some(usage) = message.get("usage").filter(|usage| usage.is_object())
                        {
                            self.usage = Some(parse_anthropic_usage(usage));
                        }
                        self.served = message
                            .get("model")
                            .and_then(JsonValue::as_str)
                            .map(str::to_owned);
                    }
                    Some("message_delta") => {
                        let Some(delta) = event.get("usage").filter(|usage| usage.is_object())
                        else {
                            return;
                        };
                        // A delta usually carries output alone: it never
                        // erases the input the start reported.
                        let parsed = parse_anthropic_usage(delta);
                        let usage = self.usage.get_or_insert_with(LlmUsage::zero);
                        if delta.get("input_tokens").is_some() {
                            usage.input = parsed.input;
                        }
                        if delta.get("output_tokens").is_some() {
                            usage.output = parsed.output;
                        }
                    }
                    Some("message_stop") => self.terminal = true,
                    _ => {}
                }
            }
        }
    }
}
