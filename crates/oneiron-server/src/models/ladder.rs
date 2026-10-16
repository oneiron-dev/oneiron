//! One role's ladder under a run: the engine sees a single seat model; each
//! rung a call reaches is admitted on its own one-use permit and sent through
//! the run's gate for that rung's offer, and a rung that fails hands the call
//! to the next.
use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::llm::run_admission::{CallOutcome, RunAdmission, RunCall, RunPermit};
use oneiron::{
    ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmUsage, ModelId,
};
use tokio::sync::mpsc::Sender;

use super::driven::Driven;
use super::offer::ServedOffer;
use super::served::served_receipt;

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
    /// it were tried and failed.
    fn stamp(&self, failed: usize, raw_provider: serde_json::Value) -> serde_json::Value {
        served_receipt(
            &self.provider,
            &self.wire_model,
            self.position,
            failed,
            raw_provider,
        )
    }
}

/// A rung that fails hands the call on, unless the run refused it: the next
/// rung's admission meets the same line.
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
        LlmError::Fatal(FatalLlmError::LabelRead(_)) => "label_read",
        LlmError::BudgetDenied(BudgetDenied::Exhausted) => "budget_exhausted",
        LlmError::BudgetDenied(BudgetDenied::LeaseInvalid) => "lease_invalid",
        LlmError::BudgetDenied(BudgetDenied::AdmissionDenied) => "admission_denied",
    }
}

fn falls_through(error: &LlmError) -> bool {
    !matches!(error, LlmError::BudgetDenied(_))
}

/// Settles a rung that did not answer. One that started keeps its
/// reservation as spend; one admitted and never sent never started its
/// lease, so its reservation is released and it pays nothing. A settlement
/// the meter refuses is on the run's `Settled` row.
fn settle_failed(permit: RunPermit) {
    if let Err(denied) = permit.settle(CallOutcome::Failed) {
        tracing::error!(%denied, "a failed rung's settlement was refused");
    }
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
}

impl OfferLadder {
    pub(super) fn seat(name: ModelId, rungs: Vec<LadderRung>) -> Self {
        Self {
            name,
            rungs,
            receipt: true,
        }
    }

    /// A configured model called by its own engine id.
    pub(super) fn bare(rung: LadderRung) -> Self {
        Self {
            name: rung.model.clone(),
            rungs: vec![rung],
            receipt: false,
        }
    }

    /// A host-injected backend serving `request`'s model as one offer.
    pub(crate) fn injected(offer: ServedOffer) -> Self {
        let model = offer.binding.model.clone();
        Self::bare(LadderRung {
            provider: offer.binding.route.adapter().to_owned(),
            position: 0,
            wire_model: model.as_str().to_owned(),
            model,
            prompt: None,
            offer,
        })
    }

    /// The id callers name.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.name
    }

    /// How many provider calls a call that fails makes: one per rung.
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
    fn answered(&self, index: usize, mut usage: LlmUsage) -> LlmUsage {
        if self.receipt {
            let raw = std::mem::take(&mut usage.raw_provider);
            usage.raw_provider = self.rungs[index].stamp(index, raw);
        }
        usage
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
        let mut last = None;
        for (index, rung) in self.rungs.iter().enumerate() {
            if !may_send() {
                break;
            }
            let (call, permit) = self.admit(run, rung, &request, selector, false)?;
            if !may_send() {
                // Unsent: only the gate starts a lease, so this pays nothing.
                settle_failed(permit);
                break;
            }
            let gate = run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
            match gate.generate(call, permit.lease()).await {
                Ok(mut response) => {
                    permit.settle(CallOutcome::Answered(&response.usage))?;
                    response.usage = self.answered(index, response.usage);
                    return Ok(response);
                }
                Err(error) => {
                    settle_failed(permit);
                    if !falls_through(&error) {
                        return Err(error);
                    }
                    tracing::warn!(seat = %self.name, rung = rung.position, provider = %rung.provider, kind = failure_kind(&error), "rung failed; trying the next");
                    last = Some(error);
                }
            }
        }
        Err(last.unwrap_or_else(|| FatalLlmError::InvalidRequest.into()))
    }

    /// One call under `run` as a stream. The first rung is admitted now, so a
    /// call the run refuses is refused before anything starts. A rung whose
    /// stream fails before its first event hands the call on; once a rung
    /// has spoken, its stream is the answer, cut or whole. Dropping the
    /// stream ends the call and settles its rung as failed.
    pub fn stream(
        self: &Arc<Self>,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmStream<'static>> {
        self.admits(&request)?;
        let first = self.admit(run, &self.rungs[0], &request, selector, true)?;
        let (ladder, run) = (Arc::clone(self), run.clone());
        let selector = selector.map(str::to_owned);
        Ok(LlmStream::new(Driven::new(move |events| async move {
            ladder
                .stream_rungs(&run, &request, selector.as_deref(), first, &events)
                .await;
        })))
    }

    async fn stream_rungs(
        &self,
        run: &RunAdmission,
        request: &LlmRequest,
        selector: Option<&str>,
        first: (LlmRequest, RunPermit),
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) {
        let mut admitted = Some(first);
        let mut last = None;
        for (index, rung) in self.rungs.iter().enumerate() {
            let next = match admitted.take() {
                Some(first) => Ok(first),
                None => self.admit(run, rung, request, selector, true),
            };
            let (call, permit) = match next {
                Ok(next) => next,
                Err(error) => {
                    let _ = events.send(Err(error)).await;
                    return;
                }
            };
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
                            usage: self.answered(index, usage),
                            finish_reason,
                        }),
                        Err(denied) => Err(denied.into()),
                    };
                    let _ = events.send(done).await;
                    return;
                }
                Ended::Failed { error, spoken } => {
                    settle_failed(permit);
                    if spoken || !falls_through(&error) {
                        let _ = events.send(Err(error)).await;
                        return;
                    }
                    tracing::warn!(seat = %self.name, rung = rung.position, kind = failure_kind(&error), "rung stream failed before its first event; trying the next");
                    last = Some(error);
                }
                Ended::Gone => return,
            }
        }
        let error = last.unwrap_or_else(|| FatalLlmError::InvalidRequest.into());
        let _ = events.send(Err(error)).await;
    }
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
