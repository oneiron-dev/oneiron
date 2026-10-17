//! One role's ladder under a run: the engine sees a single seat model; each
//! rung a call reaches is admitted on its own one-use permit and sent through
//! the run's gate for that rung's offer, and a rung that fails hands the call
//! to the next. An offer refused for a quota or a limit rests (a rate limit
//! for a backoff, a spent window until its reset, spent credit until the
//! owner clears it) and the same request goes to the next offer; while only
//! rests stop the call, it waits for the first offer back and tries again,
//! until its wait budget is spent. Once every rung has parked, the owner
//! is asked about each offer parked on spent quota, and a call whose
//! parked offer the owner gave a fallback goes there instead. A request
//! error ends the call.
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::SpentKind;
use oneiron::llm::media::MediaRequest;
use oneiron::llm::run_admission::{CallOutcome, RunAdmission, RunCall, RunDenied, RunPermit};
use oneiron::{
    ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmUsage,
    ModelId, RetryableLlmError,
};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc::Sender;

use super::cooldown::{Asked, OfferCooldowns, Refusal, Rest, leaves_device};
use super::driven::Driven;
use super::forward::{Ended, forward};
use super::media::{HeldJob, MediaAnswer, MediaRung};
use super::offer::ServedOffer;
use super::served::served_receipt;
use super::walk::{Passed, Walk, ends_call, failure_kind, provider_down};

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
    /// A media seat's rung: the media wire it sends `ai.*` media calls
    /// through, and what it serves. A chat rung has none.
    pub(super) media: Option<MediaRung>,
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
                media: None,
            },
            OfferCooldowns::unkept(),
        )
    }

    /// The id callers name.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.name
    }

    /// Bind one traceless turn without retained cooldowns, fallback logs or
    /// receipts. Only the house target keeps the host's configured prompt.
    pub(crate) fn anonymous_call(
        &self,
        request: LlmRequest,
        include_prompt: bool,
    ) -> LlmResult<(LlmRequest, ServedOffer)> {
        self.admits(&request)?;
        if self.kept_on_device(0, &request) {
            return Err(RetryableLlmError::KeptOnDevice {
                retry_after: None,
                resets_at: Vec::new(),
            }
            .into());
        }
        let mut rung = self.rungs[0].clone();
        if !include_prompt {
            rung.prompt = None;
        }
        Ok((rung.bind(request), rung.offer))
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
    fn passes_over(&self, call: Call<'_>, index: usize, walk: &mut Walk) -> bool {
        if self.kept_on_device(index, call.request) {
            self.hold(call, index, walk);
            return true;
        }
        let rung = &self.rungs[index];
        let Some(rest) = self.rests.resting(&rung.offer.binding, &rung.wire_model) else {
            return false;
        };
        walk.note(index, Passed::Resting { rest });
        true
    }

    /// Whether every rung of this ladder rests now.
    pub(super) fn rests_now(&self) -> bool {
        self.rungs.iter().all(|rung| {
            self.rests
                .resting(&rung.offer.binding, &rung.wire_model)
                .is_some()
        })
    }

    /// Once every rung the call met has parked, the owner's question about
    /// each one parked on a spent window or spent credit (OF-305: asked only
    /// when no rung is left to serve the call).
    fn ask_parked(&self, walk: &Walk) {
        let Some(parked) = walk.parked(self.rungs.len()) else {
            return;
        };
        let own: Vec<&str> = self
            .rungs
            .iter()
            .map(|rung| rung.provider.as_str())
            .collect();
        for (index, rest) in parked {
            let rung = &self.rungs[index];
            let asked = Asked {
                provider: &rung.provider,
                wire_model: &rung.wire_model,
                media: rung.media.is_some(),
            };
            self.rests.ask(&rung.offer.binding, rest, asked, &own);
        }
    }

    /// Once every rung the call met has parked, the fallback the owner named
    /// for the first parked offer that has one (`use_fallback`), while that
    /// model's offer is in rotation and the call's world may go where it
    /// runs. A media call has none.
    fn fallback(&self, call: Call<'_>, walk: &Walk) -> Option<Arc<OfferLadder>> {
        walk.parked(self.rungs.len())?
            .into_iter()
            .filter(|(index, _)| self.rungs[*index].media.is_none())
            .find_map(|(index, _)| {
                let rung = &self.rungs[index];
                self.rests
                    .fallback_for(&rung.offer.binding, &rung.wire_model)
                    .filter(|fallback| !fallback.rests_now())
                    .filter(|fallback| {
                        !fallback
                            .rungs
                            .iter()
                            .any(|rung| leaves_device(&rung.offer.binding))
                            || self.rests.world_may_leave(call.request)
                    })
            })
    }

    /// Keeps the call's work from the rung at `index`, a fallback that would
    /// take it off the device. A held call is never silent: the first time
    /// this call is held from that rung, the run's receipts get a `Denied`
    /// row for it.
    fn hold(&self, call: Call<'_>, index: usize, walk: &mut Walk) {
        let first = !walk.held_from(index);
        walk.note(index, Passed::KeptOnDevice);
        if !first {
            return;
        }
        let rung = &self.rungs[index];
        call.run.refuse(
            Some(call.selector.unwrap_or(self.name.as_str())),
            rung.model.as_str(),
            RunDenied::KeptOnDevice,
        );
        tracing::info!(
            rung = rung.position,
            reason = "world_stays_on_device",
            "a fallback would take the work off the device; passed over"
        );
    }

    /// The first rung in order that this pass of the call has not `sent`
    /// and can use now. Each is asked again every time, so a rung whose rest
    /// ended while a later one was sent is the next one used.
    fn next_rung(&self, call: Call<'_>, sent: &[bool], walk: &mut Walk) -> Option<usize> {
        (0..self.rungs.len()).find(|index| !sent[*index] && !self.passes_over(call, *index, walk))
    }

    /// Rests the offer at `index` when `error` is a limit refusal: a rate
    /// limit for its wait or a backoff, a spent window until its reset,
    /// spent credit until the owner clears it (OF-305).
    fn rest_if_limited(&self, index: usize, error: &LlmError) -> Option<Option<Rest>> {
        let refusal = match error {
            LlmError::Retryable(RetryableLlmError::RateLimited {
                retry_after,
                resets_at,
            }) => Refusal {
                retry_after: *retry_after,
                resets_at,
                spent: None,
            },
            LlmError::Retryable(RetryableLlmError::QuotaSpent {
                kind,
                retry_after,
                resets_at,
            }) => Refusal {
                retry_after: *retry_after,
                resets_at,
                spent: Some(*kind),
            },
            _ => return None,
        };
        let rung = &self.rungs[index];
        let rest = self
            .rests
            .rest(&rung.offer.binding, &rung.wire_model, refusal);
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
    /// it went out. A limit refusal rests its offer and hands the call on; an
    /// offer whose provider is down rests for its health and hands it on
    /// (OF-305), as does any other failure; a request error or a run's
    /// refusal ends the call with that error, unchanged.
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
            None if provider_down(&error) => {
                let rung = &self.rungs[index];
                let rest = self
                    .rests
                    .failed_down(&rung.offer.binding, &rung.wire_model);
                tracing::warn!(
                    rung = rung.position,
                    kind,
                    "rung's provider is down; trying the next"
                );
                Passed::Down { kind, rest, sent }
            }
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
    /// offer back. Each rung is judged again first, one already sent too, so
    /// the wait goes only to an offer the call may use now.
    fn waits_for(&self, call: Call<'_>, walk: &mut Walk, budget_secs: u64) -> Option<Back> {
        if !walk.limited() {
            return None;
        }
        for index in 0..self.rungs.len() {
            if self.kept_on_device(index, call.request) {
                self.hold(call, index, walk);
            }
        }
        let (index, at) = walk.back()?;
        let wait = at.saturating_sub(self.rests.now()?);
        (wait <= budget_secs).then(|| Back {
            index,
            at,
            wait: Duration::from_secs(wait),
        })
    }

    /// The call's end with no answer. A call kept from a rung that would
    /// take its work off the device is kept on it, with the earliest time a
    /// resting offer it may use is back, if one rests. Otherwise a last
    /// failure that was a limit refusal, or a call that reached no rung
    /// because each one it could use rests, refuses with that time, so a
    /// caller can say when. Any other last failure is returned as it came,
    /// as is an outage: every rung resting rests for its health, so the call
    /// ends with its provider's own failure, never a rate refusal.
    /// Every rung parked, the owner is asked about the spent ones.
    fn unanswered(&self, walk: Walk) -> LlmError {
        self.ask_parked(&walk);
        if walk.outage() && !walk.kept() {
            return walk
                .last
                .unwrap_or_else(|| RetryableLlmError::ServerError.into());
        }
        let back = walk
            .back()
            .zip(self.rests.now())
            .map(|((_, back), now)| (Some(back.saturating_sub(now)), vec![back]));
        if walk.kept() {
            let (retry_after, resets_at) = back.unwrap_or_default();
            return RetryableLlmError::KeptOnDevice {
                retry_after,
                resets_at,
            }
            .into();
        }
        // Every offer the call could use is parked on spent credit: no
        // reset brings one back, only the owner.
        if back
            .as_ref()
            .is_some_and(|(_, resets)| resets == &[u64::MAX])
            && walk.limited()
        {
            return RetryableLlmError::QuotaSpent {
                kind: SpentKind::Credit,
                retry_after: None,
                resets_at: Vec::new(),
            }
            .into();
        }
        match back.filter(|_| walk.limited()) {
            Some((retry_after, resets_at)) => RetryableLlmError::RateLimited {
                retry_after,
                resets_at,
            }
            .into(),
            None => walk
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
    /// can wait on the run's receipts, and through a wait for an offer back.
    /// Once it says no, no rung is sent (an admitted one settles unstarted,
    /// for nothing), and the call fails with the last rung's error (an
    /// invalid request when none went out).
    pub async fn generate_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<LlmResponse> {
        let budget = Duration::from_secs(self.rests.max_wait_secs());
        self.generate_within(run, request, selector, may_send, budget)
            .await
    }

    /// [`Self::generate_while`] for a caller with its own deadline: the
    /// call waits for offers back for at most `wait_budget` in all, the
    /// vault's longest wait or not (OF-305: a rate-limited chain backs off
    /// and retries until the caller's deadline).
    pub async fn generate_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        self.generate_from(run, request, selector, may_send, wait_budget, true)
            .await
    }

    /// [`Self::generate_within`]; once every rung has parked, a call whose
    /// parked offer has the owner's fallback goes there, when
    /// `may_fall_back` (a fallback's own call falls back no further). Boxed,
    /// since a fallback's call is this one again.
    fn generate_from<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: LlmRequest,
        selector: Option<&'a str>,
        may_send: &'a (dyn Fn() -> bool + Sync),
        wait_budget: Duration,
        may_fall_back: bool,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.walk_generate(run, request, selector, may_send, wait_budget, may_fall_back)
                .await
        })
    }

    async fn walk_generate(
        &self,
        run: &RunAdmission,
        mut request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
        may_fall_back: bool,
    ) -> LlmResult<LlmResponse> {
        self.admits(&request)?;
        // The run is live until this call ends: the host stays awake for it.
        let _awake = oneiron_vault_contract::host_adapters::run_awake();
        let call = Call {
            run,
            request: &request,
            selector,
        };
        let mut walk = Walk::default();
        let mut budget = wait_budget.as_secs();
        // The chain, each rung at most once a pass; then, while only rests
        // stopped it, the owner's fallback, or a wait for its first offer
        // back and the chain again, until the waits would pass the call's
        // budget.
        for pass in 0.. {
            if pass > 0 {
                if may_fall_back && let Some(fallback) = self.fallback(call, &walk) {
                    request.model = fallback.model().clone();
                    let fell = fallback
                        .generate_from(
                            run,
                            request,
                            selector,
                            may_send,
                            Duration::from_secs(budget),
                            false,
                        )
                        .await;
                    if fell.is_err() {
                        self.ask_parked(&walk);
                    }
                    return fell;
                }
                let Some(back) = self
                    .waits_for(call, &mut walk, budget)
                    .filter(|_| may_send())
                else {
                    break;
                };
                // Each wait spends at least a second, so a chain ends.
                budget = budget.saturating_sub(back.wait.as_secs().max(1));
                self.rests.wait(back.wait, back.at, may_send).await;
            }
            let mut sent = vec![false; self.rungs.len()];
            loop {
                if !may_send() {
                    return Err(self.unanswered(walk));
                }
                let Some(index) = self.next_rung(call, &sent, &mut walk) else {
                    break;
                };
                sent[index] = true;
                match self.send(call, index, may_send, &mut walk).await? {
                    Sent::Answer(response) => return Ok(response),
                    Sent::Failed | Sent::Held => {}
                    Sent::Stopped => return Err(self.unanswered(walk)),
                }
            }
        }
        Err(self.unanswered(walk))
    }

    /// Sends the call to the rung at `index`. A failure that ends the call
    /// is the error.
    async fn send(
        &self,
        call: Call<'_>,
        index: usize,
        may_send: &(dyn Fn() -> bool + Sync),
        walk: &mut Walk,
    ) -> LlmResult<Sent> {
        let rung = &self.rungs[index];
        let (bound, permit) = self.admit(call.run, rung, call.request, call.selector, false)?;
        if !may_send() {
            // Unsent: only the gate starts a lease, so this pays nothing.
            settle_failed(permit);
            return Ok(Sent::Stopped);
        }
        // Admission can wait on the run's receipts, and the world settings
        // can change meanwhile: the world is judged again right before the
        // rung is sent.
        if self.kept_on_device(index, call.request) {
            settle_failed(permit);
            self.hold(call, index, walk);
            return Ok(Sent::Held);
        }
        let gate = call
            .run
            .gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        match gate.generate(bound, permit.lease()).await {
            Ok(mut response) => {
                self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
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

    /// One media call (`ai.image`, `ai.video`, ...) under `run`, on the
    /// same walk as a text call: each rung it reaches whose row serves the
    /// call is admitted on its own permit, sent through the run's media gate
    /// and settled on its own, in token units; an offer refused for a limit
    /// rests and the call goes to the next, and a chain that only rests
    /// waits once for its first offer back. A job (`ai.video`) answers with
    /// its started permit held, to settle when the job ends.
    pub(super) async fn media(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        selector: Option<&str>,
    ) -> LlmResult<MediaAnswer> {
        let admission = request.admission_request();
        self.admits(&admission)?;
        let call = Call {
            run,
            request: &admission,
            selector,
        };
        let mut walk = Walk::default();
        let mut budget = self.rests.max_wait_secs();
        for pass in 0.. {
            if pass > 0 {
                let Some(back) = self.waits_for(call, &mut walk, budget) else {
                    break;
                };
                // Each wait spends at least a second, so a chain ends.
                budget = budget.saturating_sub(back.wait.as_secs().max(1));
                self.rests.wait(back.wait, back.at, &|| true).await;
            }
            let mut sent = vec![false; self.rungs.len()];
            while let Some(index) = self.next_rung(call, &sent, &mut walk) {
                sent[index] = true;
                if let Some(answer) = self.send_media(call, index, &request, &mut walk).await? {
                    return Ok(answer);
                }
            }
        }
        Err(self.unanswered(walk))
    }

    /// Sends the media call to the rung at `index`: its answer, `None` when
    /// the call goes on, or the failure that ends it.
    async fn send_media(
        &self,
        call: Call<'_>,
        index: usize,
        request: &MediaRequest,
        walk: &mut Walk,
    ) -> LlmResult<Option<MediaAnswer>> {
        let rung = &self.rungs[index];
        let Some(media) = &rung.media else {
            return Ok(None);
        };
        let mut bound = request.clone();
        bound.model = rung.model.clone();
        bound.envelope.locality = rung.offer.binding.locality;
        // A rung whose row does not serve the call (its inputs, its
        // references) is passed, unsent; a call no rung serves is refused.
        if media.row.admit_media(&bound).is_err() {
            return Ok(None);
        }
        let selector = Some(call.selector.unwrap_or(self.name.as_str()));
        let permit = call
            .run
            .admit_media(selector, &bound, &rung.offer.binding)?;
        if self.kept_on_device(index, call.request) {
            settle_failed(permit);
            self.hold(call, index, walk);
            return Ok(None);
        }
        let gate = call
            .run
            .media_gate(Arc::clone(&media.backend), &rung.offer.binding);
        let operation = request.operation;
        if operation.is_job() {
            let submitted = gate.submit(bound, permit.lease()).await;
            return match submitted {
                Ok(provider_job) => Ok(Some(MediaAnswer::Job(HeldJob {
                    gate,
                    permit: Some(permit),
                    provider_job,
                    model: rung.model.clone(),
                    operation,
                    caps: media.caps.clone(),
                }))),
                Err(error) => {
                    let sent = settle_failed(permit);
                    self.failed(index, error, sent, walk)?;
                    Ok(None)
                }
            };
        }
        let answered = gate.run(bound, permit.lease()).await;
        match answered {
            Ok(mut response) => {
                self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
                permit.settle_media(response.usage.token_units(operation, &media.caps))?;
                if self.receipt {
                    let raw = std::mem::take(&mut response.usage.raw_provider);
                    response.usage.raw_provider =
                        rung.stamp(walk.went_out(), walk.passed_over(&self.rungs), raw);
                }
                Ok(Some(MediaAnswer::Done(response)))
            }
            Err(error) => {
                let sent = settle_failed(permit);
                self.failed(index, error, sent, walk)?;
                Ok(None)
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
        self.stream_from(run, request, selector, true)
    }

    /// [`Self::stream`]; a stream that opens with every rung parked goes to
    /// the owner's fallback for a parked offer, when `may_fall_back` (a
    /// fallback's own stream falls back no further).
    fn stream_from(
        self: &Arc<Self>,
        run: &RunAdmission,
        mut request: LlmRequest,
        selector: Option<&str>,
        may_fall_back: bool,
    ) -> LlmResult<LlmStream<'static>> {
        self.admits(&request)?;
        let call = Call {
            run,
            request: &request,
            selector,
        };
        let mut walk = Walk::default();
        let (start, wait) =
            match (0..self.rungs.len()).find(|index| !self.passes_over(call, *index, &mut walk)) {
                Some(start) => (start, None),
                None => {
                    if may_fall_back && let Some(fallback) = self.fallback(call, &walk) {
                        request.model = fallback.model().clone();
                        let fell = fallback.stream_from(run, request, selector, false);
                        if fell.is_err() {
                            self.ask_parked(&walk);
                        }
                        return fell;
                    }
                    match self.waits_for(call, &mut walk, self.rests.max_wait_secs()) {
                        Some(back) => (back.index, Some(back)),
                        None => return Err(self.unanswered(walk)),
                    }
                }
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
        let call = Call {
            run,
            request,
            selector,
        };
        let mut held = Some((start, first));
        let mut wait = wait;
        // A stream that opened with every usable offer resting admitted the
        // first one back. When that admission saw the world kept on the
        // device, the rung is settled unsent and every rung is judged again,
        // so the one wait goes to an offer the call may use now, or none.
        if let Some(back) = wait
            && self.kept_on_device(back.index, request)
        {
            if let Some((_, (_, permit))) = held.take() {
                settle_failed(permit);
            }
            let mut usable = false;
            for index in 0..self.rungs.len() {
                usable |= !self.passes_over(call, index, &mut walk);
            }
            wait = None;
            if !usable {
                let Some(back) = self.waits_for(call, &mut walk, self.rests.max_wait_secs()) else {
                    let _ = events.send(Err(self.unanswered(walk))).await;
                    return;
                };
                wait = Some(back);
            }
        }
        // The chain; then, while only rests stopped it, a wait for its first
        // offer back and the chain again, until the waits would pass the
        // vault's longest wait in all (OF-305). A stream that opened with
        // every usable offer resting starts with that wait.
        let mut budget = self.rests.max_wait_secs();
        let mut back = match wait {
            Some(back) => Some(back),
            None => match self
                .stream_pass(run, request, selector, &mut held, &mut walk, events)
                .await
            {
                Flow::Ended => return,
                Flow::On => self.waits_for(call, &mut walk, budget),
            },
        };
        while let Some(next) = back {
            budget = budget.saturating_sub(next.wait.as_secs().max(1));
            // Dropping the stream drops this wait: nothing else stops it.
            self.rests.wait(next.wait, next.at, &|| true).await;
            back = match self
                .stream_pass(run, request, selector, &mut held, &mut walk, events)
                .await
            {
                Flow::Ended => return,
                Flow::On => self.waits_for(call, &mut walk, budget),
            };
        }
        if let Some((_, (_, permit))) = held {
            settle_failed(permit);
        }
        let _ = events.send(Err(self.unanswered(walk))).await;
    }

    /// One pass of a stream's chain: each rung the call can use, first in
    /// order first and each at most once, until one ends the call. `held` is
    /// the rung admitted before the stream started: the pass sends it when it
    /// comes to it, and settles it unsent, for nothing, before it sends
    /// another.
    async fn stream_pass(
        &self,
        run: &RunAdmission,
        request: &LlmRequest,
        selector: Option<&str>,
        held: &mut Option<(usize, (LlmRequest, RunPermit))>,
        walk: &mut Walk,
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) -> Flow {
        let call = Call {
            run,
            request,
            selector,
        };
        let mut sent = vec![false; self.rungs.len()];
        while let Some(index) = self.next_rung(call, &sent, walk) {
            sent[index] = true;
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
            // The world is judged again right before the rung is sent: its
            // admission, or the wait a held first rung sat through, may have
            // outlasted the world settings it was judged by.
            if self.kept_on_device(index, request) {
                settle_failed(next.1);
                self.hold(call, index, walk);
                continue;
            }
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
                self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
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
                // Its stream was the answer, never sent again; a limit it
                // met still rests it, as does an outage.
                if self.rest_if_limited(index, &error).is_none() && provider_down(&error) {
                    self.rests
                        .failed_down(&rung.offer.binding, &rung.wire_model);
                }
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

/// One call on its way down the ladder: its run, its request, and what the
/// caller named it by.
#[derive(Clone, Copy)]
struct Call<'a> {
    run: &'a RunAdmission,
    request: &'a LlmRequest,
    selector: Option<&'a str>,
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
    /// It was kept from the work, unsent, and the call goes on.
    Held,
    /// `may_send` said no once it was admitted: the call stops.
    Stopped,
}

/// Whether a streamed call goes on to the next rung.
enum Flow {
    On,
    Ended,
}

impl OfferLadder {
    /// Opens one bounded media stream under `run` (live `ai.transcribe`
    /// partials) on the first rung that serves it: one permit for the whole
    /// stream, reserving `bound_ms` of audio at the rung's rate, started at
    /// its media gate before any audio leaves. An open stream never moves to
    /// another rung; a voice route pins its one rung.
    pub(super) fn open_media_stream(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        bound_ms: u64,
    ) -> LlmResult<oneiron::llm::run_admission::MediaStreamLease> {
        let admission = request.admission_request();
        self.admits(&admission)?;
        let call = Call {
            run,
            request: &admission,
            selector: None,
        };
        let mut walk = Walk::default();
        for (index, rung) in self.rungs.iter().enumerate() {
            let Some(media) = &rung.media else {
                continue;
            };
            let mut bound = request.clone();
            bound.model = rung.model.clone();
            bound.envelope.locality = rung.offer.binding.locality;
            if media.row.admit_media(&bound).is_err() || self.passes_over(call, index, &mut walk) {
                continue;
            }
            let reserve = oneiron::llm::run_admission::MediaStreamLease::reserve_units(
                bound.operation,
                &media.caps,
                bound_ms,
            );
            let permit = run.admit_media_stream(
                Some(self.name.as_str()),
                &bound,
                &rung.offer.binding,
                reserve,
            )?;
            let gate = run.media_gate(Arc::clone(&media.backend), &rung.offer.binding);
            return gate.open_stream(&bound, permit, media.caps.clone(), bound_ms);
        }
        Err(self.unanswered(walk))
    }
}
