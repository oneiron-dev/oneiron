//! One role's ladder under a run: the engine sees a single seat model; each
//! rung a call reaches is admitted on its own one-use permit and sent through
//! the run's gate for that rung's offer, and a rung that fails hands the call
//! to the next. An offer refused for a quota or a limit rests until its reset
//! and the same request goes to the next offer; a request error ends the call.
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use oneiron::llm::run_admission::{CallOutcome, RunAdmission, RunCall, RunPermit};
use oneiron::{
    ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmUsage, ModelId,
    RetryableLlmError,
};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc::Sender;

use super::cooldown::{OfferCooldowns, Rest, leaves_device};
use super::driven::Driven;
use super::offer::ServedOffer;
use super::served::served_receipt;
use super::walk::{Passed, Walk};

/// One rung: a provider's offer for one model, and the instruction prepended
/// to every call it serves.
#[derive(Clone)]
pub(super) struct LadderRung {
    pub(super) provider: String,
    /// Where the rung sits in the configured ladder, the receipt's `rung`:
    /// a rung served alone, or after an unavailable one, keeps its number.
    pub(super) position: usize,
    pub(super) model: ModelId,
    pub(super) wire_model: String,
    pub(super) prompt: Option<String>,
    pub(super) offer: ServedOffer,
}

impl LadderRung {
    /// The call as this rung sends it: its model at its route, its
    /// instruction first.
    fn bind(&self, mut request: LlmRequest) -> LlmRequest {
        request.model = self.model.clone();
        request.envelope.locality = self.offer.binding.locality;
        if let Some(prompt) = &self.prompt {
            request.messages.insert(
                0,
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: prompt.clone(),
                    }],
                },
            );
        }
        request
    }

    /// The receipt of an answer this rung gave after `failed` rungs before
    /// it were tried and failed, and the rungs `passed_over` before it.
    fn stamp(&self, failed: usize, passed_over: JsonValue, raw_provider: JsonValue) -> JsonValue {
        served_receipt(
            &self.provider,
            &self.wire_model,
            self.position,
            failed,
            passed_over,
            raw_provider,
        )
    }
}

/// The closed class of a rung failure. An unsupported capability's reason is
/// a provider's own words, so the log carries the class and not the error.
fn failure_kind(error: &LlmError) -> &'static str {
    use oneiron::RetryableLlmError;
    use oneiron::llm::BudgetDenied;
    match error {
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => "rate_limited",
        LlmError::Retryable(RetryableLlmError::ServerError) => "server_error",
        LlmError::Retryable(RetryableLlmError::Timeout) => "timeout",
        LlmError::Retryable(RetryableLlmError::StreamCut) => "stream_cut",
        LlmError::Fatal(FatalLlmError::InvalidRequest) => "invalid_request",
        LlmError::Fatal(FatalLlmError::Auth) => "auth",
        LlmError::Fatal(FatalLlmError::ContentFiltered) => "content_filtered",
        LlmError::Fatal(FatalLlmError::EmptyResponse) => "empty_response",
        LlmError::Fatal(FatalLlmError::Unsupported(_)) => "unsupported",
        LlmError::BudgetDenied(BudgetDenied::Exhausted) => "budget_exhausted",
        LlmError::BudgetDenied(BudgetDenied::LeaseInvalid) => "lease_invalid",
        LlmError::BudgetDenied(BudgetDenied::AdmissionDenied) => "admission_denied",
    }
}

/// A failure that ends the call as it came: the request itself failed (a
/// 400, filtered content, a capability it needs), so the next offer would
/// fail it too, or the run refused it, so the next rung's admission meets the
/// same line. Every other failure hands the call on.
fn ends_call(error: &LlmError) -> bool {
    matches!(
        error,
        LlmError::Fatal(
            FatalLlmError::InvalidRequest
                | FatalLlmError::ContentFiltered
                | FatalLlmError::Unsupported(_)
        ) | LlmError::BudgetDenied(_)
    )
}

/// Settles a rung that did not answer, and says whether it went out. One
/// that started keeps its reservation as spend; one admitted and never sent
/// never started its lease, so its reservation is released and it pays
/// nothing. A settlement the meter refuses is on the run's `Settled` row.
fn settle_failed(permit: RunPermit) -> bool {
    let sent = permit.dispatched();
    if let Err(denied) = permit.settle(CallOutcome::Failed) {
        tracing::error!(%denied, "a failed rung's settlement was refused");
    }
    sent
}

/// What one rung's stream came to.
enum Ended {
    Done {
        message: LlmMessage,
        usage: LlmUsage,
        finish_reason: oneiron::llm::FinishReason,
    },
    Failed {
        error: LlmError,
        spoken: bool,
    },
    /// The caller stopped reading, or the stream ended with no terminal.
    Gone,
}

/// How a model is reached: a seat's ladder, one rung of it alone, or a
/// configured model by its own id. Every model call this server makes goes
/// through one of these under a run, never to a provider backend directly.
pub struct OfferLadder {
    name: ModelId,
    rungs: Vec<LadderRung>,
    /// An answer carries the ladder's served receipt (a seat, or a rung of
    /// one), or the provider's usage as it came (a model called by its id).
    receipt: bool,
    /// The one model a caller or a manifest named: its one rung is that
    /// pick, never a fallback.
    picked: bool,
    /// Where an offer refused for a limit rests until its reset.
    rests: Arc<OfferCooldowns>,
}

impl OfferLadder {
    pub(super) fn seat(name: ModelId, rungs: Vec<LadderRung>, rests: Arc<OfferCooldowns>) -> Self {
        Self {
            name,
            rungs,
            receipt: true,
            picked: false,
            rests,
        }
    }

    /// One rung of a seat, served alone where a manifest pins its model.
    pub(super) fn pinned(rung: LadderRung, rests: Arc<OfferCooldowns>) -> Self {
        Self {
            name: rung.model.clone(),
            rungs: vec![rung],
            receipt: true,
            picked: true,
            rests,
        }
    }

    /// A configured model called by its own engine id.
    pub(super) fn bare(rung: LadderRung, rests: Arc<OfferCooldowns>) -> Self {
        Self {
            name: rung.model.clone(),
            rungs: vec![rung],
            receipt: false,
            picked: true,
            rests,
        }
    }

    /// A host-injected backend serving `request`'s model as one offer. The
    /// host keeps its own backend's health; nothing rests here.
    pub(crate) fn injected(offer: ServedOffer) -> Self {
        let model = offer.binding.model.clone();
        Self::bare(
            LadderRung {
                provider: offer.binding.route.adapter().to_owned(),
                position: 0,
                wire_model: model.as_str().to_owned(),
                model,
                prompt: None,
                offer,
            },
            OfferCooldowns::unkept(),
        )
    }

    /// The id callers name.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.name
    }

    /// How many provider calls a call that fails makes on one pass of its
    /// chain: one per rung. A call that waits for a cooling chain makes one
    /// more pass.
    #[must_use]
    pub fn rungs(&self) -> usize {
        self.rungs.len()
    }

    /// A capability holds only if every rung has it: a fallback rung must
    /// be able to serve the very request the first rung was sent.
    #[must_use]
    pub fn supports(&self, model: &ModelId, capability: &LlmCapability) -> bool {
        *model == self.name
            && !self.rungs.is_empty()
            && self
                .rungs
                .iter()
                .all(|rung| rung.offer.backend.supports(&rung.model, capability.clone()))
    }

    fn admits(&self, request: &LlmRequest) -> LlmResult<()> {
        if request.model == self.name && !self.rungs.is_empty() {
            Ok(())
        } else {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }

    /// Admits `request` as a call of `rung` under `run`: its own permit,
    /// bound to that rung's model, route, locality and offer, and to the
    /// exact request bytes when the rung's backend builds them first (a
    /// broker rung).
    fn admit(
        &self,
        run: &RunAdmission,
        rung: &LadderRung,
        request: &LlmRequest,
        selector: Option<&str>,
        stream: bool,
    ) -> LlmResult<(LlmRequest, RunPermit)> {
        let call = rung.bind(request.clone());
        let run_call = RunCall {
            selector: Some(selector.unwrap_or(self.name.as_str())),
            request: &call,
            offer: &rung.offer.binding,
        };
        // A request the backend cannot build is admitted unbound: the gate's
        // preflight then refuses it with a denial row, before any byte leaves.
        let permit = match rung.offer.backend.request_digest(&call, stream) {
            Ok(Some(digest)) => run.admit_request(run_call, &digest)?,
            Ok(None) | Err(_) => run.admit(run_call)?,
        };
        Ok((call, permit))
    }

    /// The usage an answer of the rung at `index` reports, with this ladder's
    /// receipt. Stamped after its permit settled: the permit already charged
    /// each failed rung on its own.
    fn answered(&self, index: usize, walk: &Walk, mut usage: LlmUsage) -> LlmUsage {
        if self.receipt {
            let raw = std::mem::take(&mut usage.raw_provider);
            usage.raw_provider =
                self.rungs[index].stamp(walk.went_out(), walk.passed_over(&self.rungs), raw);
        }
        usage
    }

    /// Whether a fallback to the rung at `index` would take `request` off
    /// the device while its world stays on it. A seat's configured first
    /// rung, and the one model a caller or a manifest named, are the owner's
    /// own pick, never a fallback; a later rung is one even when no rung
    /// before it could be built.
    fn kept_on_device(&self, index: usize, request: &LlmRequest) -> bool {
        let rung = &self.rungs[index];
        !self.picked
            && rung.position > 0
            && leaves_device(&rung.offer.binding)
            && !self.rests.world_may_leave(request)
    }

    /// Whether the call passes the rung at `index` without sending it: a
    /// fallback to it would take the work off the device and the call's
    /// world stays on it, or its offer rests from an earlier refusal. The
    /// device comes first, so a rung the call may not use is never one it
    /// waits for.
    fn passes_over(&self, index: usize, request: &LlmRequest, walk: &mut Walk) -> bool {
        let rung = &self.rungs[index];
        let passed = if self.kept_on_device(index, request) {
            tracing::info!(
                rung = rung.position,
                reason = "world_stays_on_device",
                "a fallback would take the work off the device; passed over"
            );
            Passed::KeptOnDevice
        } else if let Some(until) =
            self.rests
                .resting(&rung.offer.binding, &rung.wire_model, walk.woke)
        {
            Passed::Resting { until }
        } else {
            return false;
        };
        walk.note(index, passed);
        true
    }

    /// Rests the offer at `index` when `error` is a limit refusal, until the
    /// reset it names.
    fn rest_if_limited(&self, index: usize, error: &LlmError) -> Option<Option<Rest>> {
        let LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        }) = error
        else {
            return None;
        };
        let rung = &self.rungs[index];
        let rest = self.rests.rest(
            &rung.offer.binding,
            &rung.wire_model,
            *retry_after,
            resets_at,
        );
        tracing::warn!(
            rung = rung.position,
            kind = failure_kind(error),
            reset = rest.map_or("unkept", |rest| rest.source.as_str()),
            until = rest.map_or(0, |rest| rest.until),
            "offer refused for a limit; it rests until its reset"
        );
        Some(rest)
    }

    /// Records the failure of the rung at `index`, `sent` or refused before
    /// it went out. A limit refusal rests its offer and hands the call on, as
    /// does an offer that is down; a request error or a run's refusal ends
    /// the call with that error, unchanged.
    fn failed(
        &self,
        index: usize,
        error: LlmError,
        sent: bool,
        walk: &mut Walk,
    ) -> Result<(), LlmError> {
        if ends_call(&error) {
            return Err(error);
        }
        let kind = failure_kind(&error);
        let passed = match self.rest_if_limited(index, &error) {
            Some(rest) => Passed::Refused { kind, rest, sent },
            None => {
                let rung = &self.rungs[index];
                tracing::warn!(rung = rung.position, kind, "rung failed; trying the next");
                Passed::Failed { kind, sent }
            }
        };
        walk.passed.push((index, passed));
        walk.last = Some(error);
        Ok(())
    }

    /// When the call met only rests (each rung it could use rests, or
    /// refused for a limit), the first offer back, when, and the wait until
    /// then, if that is within the vault's longest wait. The rate law: a
    /// cooling chain is not refused for rate; its call waits for the first
    /// offer back.
    fn waits_for(&self, walk: &Walk) -> Option<Back> {
        if !walk.limited() {
            return None;
        }
        let (index, at) = walk.back()?;
        let wait = at.saturating_sub(self.rests.now()?);
        (wait <= self.rests.max_wait_secs()).then(|| Back {
            index,
            at,
            wait: Duration::from_secs(wait),
        })
    }

    /// The call's end with no answer. A last failure that was a limit
    /// refusal, or a call that reached no rung because each one it could use
    /// rests, refuses with the earliest time a resting offer is back, so a
    /// caller can say when. Any other last failure is returned as it came.
    fn unanswered(&self, walk: Walk) -> LlmError {
        match (walk.limited(), walk.back(), self.rests.now()) {
            (true, Some((_, back)), Some(now)) => RetryableLlmError::RateLimited {
                retry_after: Some(back.saturating_sub(now)),
                resets_at: vec![back],
            }
            .into(),
            _ => walk
                .last
                .unwrap_or_else(|| FatalLlmError::InvalidRequest.into()),
        }
    }

    /// One call under `run`, rung by rung. Each rung that is reached is
    /// admitted, sent through the run's gate and settled on its own: an
    /// answer pays its usage (or its reservation when it reports none), a
    /// rung that failed after it went out pays its reservation. `selector`
    /// is what the caller named, for the receipt (the ladder's id if none).
    pub async fn generate(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmResponse> {
        self.generate_while(run, request, selector, &|| true).await
    }

    /// [`Self::generate`], asking `may_send` before each rung is admitted,
    /// the first one's too, and again once it is admitted, since admission
    /// can wait on the run's receipts. Once it says no, no rung is sent (an
    /// admitted one settles unstarted, for nothing), and the call fails with
    /// the last rung's error (an invalid request when none went out).
    pub async fn generate_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<LlmResponse> {
        self.admits(&request)?;
        let mut walk = Walk::default();
        // The chain, then, when only rests stopped it, the chain once more
        // after one wait for its first offer back.
        for waited in [false, true] {
            if waited {
                let Some(back) = self.waits_for(&walk).filter(|_| may_send()) else {
                    break;
                };
                tokio::time::sleep(back.wait).await;
                walk.woke = back.at;
            }
            for index in 0..self.rungs.len() {
                if !may_send() {
                    return Err(self.unanswered(walk));
                }
                if self.passes_over(index, &request, &mut walk) {
                    continue;
                }
                match self
                    .send(run, index, &request, selector, may_send, &mut walk)
                    .await?
                {
                    Sent::Answer(response) => return Ok(response),
                    Sent::Failed => {}
                    Sent::Stopped => return Err(self.unanswered(walk)),
                }
            }
        }
        Err(self.unanswered(walk))
    }

    /// Sends `request` to the rung at `index`. A failure that ends the call
    /// is the error.
    async fn send(
        &self,
        run: &RunAdmission,
        index: usize,
        request: &LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        walk: &mut Walk,
    ) -> LlmResult<Sent> {
        let rung = &self.rungs[index];
        let (call, permit) = self.admit(run, rung, request, selector, false)?;
        if !may_send() {
            // Unsent: only the gate starts a lease, so this pays nothing.
            settle_failed(permit);
            return Ok(Sent::Stopped);
        }
        let gate = run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        match gate.generate(call, permit.lease()).await {
            Ok(mut response) => {
                permit.settle(CallOutcome::Answered(&response.usage))?;
                response.usage = self.answered(index, walk, response.usage);
                Ok(Sent::Answer(response))
            }
            Err(error) => {
                let sent = settle_failed(permit);
                self.failed(index, error, sent, walk)?;
                Ok(Sent::Failed)
            }
        }
    }

    /// One call under `run` as a stream. The first rung the call can use is
    /// admitted now, so a call the run refuses, or one whose every usable
    /// offer rests past the longest wait, is refused before anything starts.
    /// A rung whose stream fails before its first event hands the call on, a
    /// quota error as that first event too; once a rung has spoken, its
    /// stream is the answer, cut or whole. Dropping the stream ends the call
    /// and settles its rung as failed.
    pub fn stream(
        self: &Arc<Self>,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmStream<'static>> {
        self.admits(&request)?;
        let mut walk = Walk::default();
        let (start, wait) = match (0..self.rungs.len())
            .find(|index| !self.passes_over(*index, &request, &mut walk))
        {
            Some(start) => (start, None),
            None => match self.waits_for(&walk) {
                Some(back) => (back.index, Some(back)),
                None => return Err(self.unanswered(walk)),
            },
        };
        let first = self.admit(run, &self.rungs[start], &request, selector, true)?;
        let (ladder, run) = (Arc::clone(self), run.clone());
        let selector = selector.map(str::to_owned);
        Ok(LlmStream::new(Driven::new(move |events| async move {
            let opening = Opening {
                start,
                first,
                wait,
                walk,
            };
            ladder
                .stream_rungs(&run, &request, selector.as_deref(), opening, &events)
                .await;
        })))
    }

    async fn stream_rungs(
        &self,
        run: &RunAdmission,
        request: &LlmRequest,
        selector: Option<&str>,
        opening: Opening,
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) {
        let Opening {
            start,
            first,
            wait,
            mut walk,
        } = opening;
        let mut held = Some((start, first));
        // The chain, then, when only rests stopped it, the chain once more
        // after one wait for its first offer back. A stream that opened with
        // every usable offer resting starts with that wait.
        let back = match wait {
            Some(back) => Some(back),
            None => match self
                .stream_pass(run, request, selector, &mut held, &mut walk, events)
                .await
            {
                Flow::Ended => return,
                Flow::On => self.waits_for(&walk),
            },
        };
        if let Some(back) = back {
            tokio::time::sleep(back.wait).await;
            walk.woke = back.at;
            if let Flow::Ended = self
                .stream_pass(run, request, selector, &mut held, &mut walk, events)
                .await
            {
                return;
            }
        }
        if let Some((_, (_, permit))) = held {
            settle_failed(permit);
        }
        let _ = events.send(Err(self.unanswered(walk))).await;
    }

    /// One pass of a stream's chain: each rung the call can use, in order,
    /// until one ends the call. `held` is the rung admitted before the
    /// stream started: the pass sends it when it reaches it in use, and
    /// settles it unsent, for nothing, before it sends another.
    async fn stream_pass(
        &self,
        run: &RunAdmission,
        request: &LlmRequest,
        selector: Option<&str>,
        held: &mut Option<(usize, (LlmRequest, RunPermit))>,
        walk: &mut Walk,
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) -> Flow {
        for index in 0..self.rungs.len() {
            if self.passes_over(index, request, walk) {
                continue;
            }
            let next = match held.take() {
                Some((at, first)) if at == index => first,
                other => {
                    if let Some((_, (_, permit))) = other {
                        settle_failed(permit);
                    }
                    match self.admit(run, &self.rungs[index], request, selector, true) {
                        Ok(next) => next,
                        Err(error) => {
                            let _ = events.send(Err(error)).await;
                            return Flow::Ended;
                        }
                    }
                }
            };
            if let Flow::Ended = self.stream_rung(run, index, next, walk, events).await {
                return Flow::Ended;
            }
        }
        Flow::On
    }

    /// Streams the rung at `index` to the caller. The call is over once the
    /// rung answers, fails after it has spoken, fails in a way that ends the
    /// call, or the caller stops reading; a rung that fails before its first
    /// event hands the call on.
    async fn stream_rung(
        &self,
        run: &RunAdmission,
        index: usize,
        (call, permit): (LlmRequest, RunPermit),
        walk: &mut Walk,
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) -> Flow {
        let rung = &self.rungs[index];
        let gate = run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        let ended = match gate.stream(call, permit.lease()) {
            Ok(stream) => forward(stream, events).await,
            Err(error) => Ended::Failed {
                error,
                spoken: false,
            },
        };
        match ended {
            Ended::Done {
                message,
                usage,
                finish_reason,
            } => {
                let done = match permit.settle(CallOutcome::Answered(&usage)) {
                    Ok(_) => Ok(LlmStreamEvent::Done {
                        message,
                        usage: self.answered(index, walk, usage),
                        finish_reason,
                    }),
                    Err(denied) => Err(denied.into()),
                };
                let _ = events.send(done).await;
                Flow::Ended
            }
            Ended::Failed {
                error,
                spoken: true,
            } => {
                settle_failed(permit);
                // Its stream was the answer; a limit it met still rests it.
                self.rest_if_limited(index, &error);
                let _ = events.send(Err(error)).await;
                Flow::Ended
            }
            Ended::Failed {
                error,
                spoken: false,
            } => {
                let sent = settle_failed(permit);
                match self.failed(index, error, sent, walk) {
                    Ok(()) => Flow::On,
                    Err(error) => {
                        let _ = events.send(Err(error)).await;
                        Flow::Ended
                    }
                }
            }
            Ended::Gone => Flow::Ended,
        }
    }
}

/// Where a stream opens: the first rung the call can use and its permit,
/// the wait for it when every usable offer rested, and what the call met on
/// the rungs before it.
struct Opening {
    start: usize,
    first: (LlmRequest, RunPermit),
    wait: Option<Back>,
    walk: Walk,
}

/// A cooling chain's first offer back: its rung, when it is back, and the
/// wait until then.
#[derive(Clone, Copy)]
struct Back {
    index: usize,
    at: u64,
    wait: Duration,
}

/// What sending one rung came to.
enum Sent {
    Answer(LlmResponse),
    /// It failed and the call goes on.
    Failed,
    /// `may_send` said no once it was admitted: the call stops.
    Stopped,
}

/// Whether a streamed call goes on to the next rung.
enum Flow {
    On,
    Ended,
}

/// Hands one rung's events to the caller until its terminal or its failure.
async fn forward(mut stream: LlmStream<'_>, events: &Sender<LlmResult<LlmStreamEvent>>) -> Ended {
    let mut spoken = false;
    loop {
        match stream.next().await {
            Some(Ok(LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
            })) => {
                return Ended::Done {
                    message,
                    usage,
                    finish_reason,
                };
            }
            Some(Ok(event)) => {
                spoken = true;
                if events.send(Ok(event)).await.is_err() {
                    return Ended::Gone;
                }
            }
            Some(Err(error)) => return Ended::Failed { error, spoken },
            // An `LlmStream` that ends before its terminal yields `StreamCut`
            // first, so this is a caller that stopped reading.
            None => return Ended::Gone,
        }
    }
}
