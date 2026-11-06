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
use std::sync::Arc;

use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::dispatch_byoa::ByoaExecutionFence;
use oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
use oneiron::llm::run_admission::{
    CallOutcome, OfferBinding, RawDispatch, RunAdmission, RunCall, RunDenied, RunPermit,
};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, EdgeActorClass, EntityId,
    LlmRequest, LlmResult, LlmUsage, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    WriteActor,
};
use oneiron_llm_anthropic::parse_anthropic_usage;
use oneiron_llm_openai::parse_openai_usage;
use serde_json::Value as JsonValue;

use crate::ai_host::live_lease::{LiveLease, LiveLeaseState};
use crate::runtime::SeatModelProtocol;
use crate::server::SyncServer;

/// The purpose a seat's model calls are admitted under.
const SEAT_MODEL_PURPOSE: &str = "seat.model";

/// The most bytes of one event line the usage reader holds while its end
/// has not arrived; a longer line is skipped, never buffered further.
const MAX_EVENT_LINE: usize = 1 << 20;

/// One seat claim's paid model calls: its run and its spend scope's lease.
pub(crate) struct SeatModelMeter {
    vault: Arc<Vault>,
    run: RunAdmission,
    lease: LiveLeaseState,
}

impl SeatModelMeter {
    /// The meter of `fence`'s claim, its calls the claim's own agent
    /// `holder`'s: the vault's budget policy for that agent, bounded by
    /// what the attempt's spend scope has left when it has one.
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
        let lease = LiveLease::new(&vault, scope, meter.clone(), limit, 0).state();
        let run = server.ai.model_runtime().funded_run(run_id, meter, None);
        Ok(Arc::new(Self { vault, run, lease }))
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
    /// `Denied` row, nothing reserved.
    pub(crate) fn refuse_unoffered(&self, wire_model: &str) -> RunDenied {
        self.run.refuse(
            None,
            oneiron::llm::run_admission::UNRESOLVED_SELECTOR,
            RunDenied::UnknownSelector {
                len: wire_model.len(),
            },
        )
    }

    /// Admits one request through `offer`, for the bytes whose digest is
    /// `digest`, before any key is read: the run's line, bounded by the
    /// scope's live room, and for a host-paid offer the vault's allocation.
    /// The call's guard settles it, whatever happens to it.
    ///
    /// # Errors
    ///
    /// The run's refusal; nothing is reserved.
    pub(crate) fn admit(
        self: &Arc<Self>,
        offer: &OfferBinding,
        wire_model: &str,
        digest: &str,
        protocol: SeatModelProtocol,
    ) -> Result<SeatModelCall, RunDenied> {
        self.book();
        let request = admission_request(offer);
        let permit = self.run.admit_request(
            RunCall {
                selector: Some(wire_model),
                request: &request,
                offer,
            },
            digest,
        )?;
        let dispatch = self.run.raw_dispatch(&permit, offer, digest, None);
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
/// `message_stop`. No reply text is kept.
struct SeatModelUsage {
    protocol: SeatModelProtocol,
    usage: Option<LlmUsage>,
    /// The model the provider said it served.
    served: Option<String>,
    /// The reply reached its protocol's end.
    terminal: bool,
    /// The event line whose end has not arrived yet.
    line: Vec<u8>,
    /// The line held is past [`MAX_EVENT_LINE`]: it is skipped to its end.
    skipping: bool,
}

impl SeatModelUsage {
    const fn new(protocol: SeatModelProtocol) -> Self {
        Self {
            protocol,
            usage: None,
            served: None,
            terminal: false,
            line: Vec::new(),
            skipping: false,
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

    /// A streamed chunk: each complete event line is read once.
    fn feed(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        while let Some(end) = rest.iter().position(|byte| *byte == b'\n') {
            let (head, tail) = rest.split_at(end);
            rest = &tail[1..];
            if self.skipping {
                self.skipping = false;
                self.line.clear();
                continue;
            }
            if self.line.is_empty() {
                self.event_line(head);
            } else {
                self.line.extend_from_slice(head);
                let line = std::mem::take(&mut self.line);
                self.event_line(&line);
            }
        }
        if self.skipping {
            return;
        }
        self.line.extend_from_slice(rest);
        if self.line.len() > MAX_EVENT_LINE {
            self.line.clear();
            self.skipping = true;
        }
    }

    /// One event line: a `data:` line that can carry usage or the end.
    fn event_line(&mut self, line: &[u8]) {
        let Some(data) = line.strip_prefix(b"data:") else {
            return;
        };
        let data = data.trim_ascii();
        match self.protocol {
            SeatModelProtocol::OpenAiChat => {
                if data == b"[DONE]" {
                    self.terminal = true;
                    return;
                }
                if !contains(data, b"\"usage\"") {
                    return;
                }
                let Ok(event) = serde_json::from_slice::<JsonValue>(data) else {
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
                if !contains(data, b"\"message_") {
                    return;
                }
                let Ok(event) = serde_json::from_slice::<JsonValue>(data) else {
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

/// Whether `haystack` holds `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
