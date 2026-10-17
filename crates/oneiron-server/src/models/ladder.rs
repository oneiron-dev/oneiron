//! One role's ladder under a run: the engine sees a single seat model; each
//! rung a call reaches is admitted on its own one-use permit and sent through
//! the run's gate for that rung's offer, and a rung that fails hands the call
//! to the next. An offer refused for a quota or a limit rests (a rate limit
//! for a backoff, a spent window until its reset, spent credit until the
//! owner clears it) and the same request goes to the next offer; while only
//! rests stop the call, it waits for the first offer back and tries again,
//! until its wait budget is spent. Once every rung has parked, the owner
//! is asked about each offer parked on spent quota, and a call whose
//! parked offer the owner gave a fallback goes there instead, a stream after
//! any pass and a media call too, as long as that model can take the call;
//! its answer keeps this ladder's receipt. An offer on
//! probation after its provider was down takes one request at a time: a call
//! that meets its probation request out passes it to the next rung, or waits
//! for that request to end. A request error ends the call.
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use oneiron::llm::SpentKind;
use oneiron::llm::media::{AiOperation, MediaFuture, MediaRequest};
use oneiron::llm::run_admission::{CallOutcome, RunAdmission, RunCall, RunDenied, RunPermit};
use oneiron::{
    ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmUsage, ModelId,
    RetryableLlmError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc::Sender;

use super::cooldown::{
    Asked, FallbackRung, OfferCooldowns, ProbeBlocked, ProbePermit, Refusal, Rest, leaves_device,
};
use super::driven::Driven;
use super::forward::{Ended, forward};
use super::media::{HeldJob, MediaAnswer, MediaRung, RetryHint, RungVoices};
use super::offer::ServedOffer;
use super::served::served_receipt;
use super::status::RungHealth;
use super::walk::{Passed, Walk, ends_call, failure_kind, provider_down};

/// A chat call's answer and the model of the rung that gave it.
type ServedFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = LlmResult<(LlmResponse, ModelId)>> + Send + 'a>,
>;

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

    /// Names this rung as the one that answered `request` (before its
    /// binding), for the step replay capsule a capture on this thread waits
    /// to finalize (FIX 3028): its model, where it ran and the prompt it put
    /// first, so the capsule holds what was really sent.
    fn note_answered(&self, request: &LlmRequest) {
        oneiron::code_run::note_answering_rung(
            request,
            &self.model,
            self.offer.binding.locality,
            self.prompt.as_deref(),
        );
    }
}

/// The wire a ladder's calls speak. An owner's fallback for its parked
/// offers must speak the same one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Wire {
    #[default]
    Chat,
    Rerank,
    Media(AiOperation),
}

/// What an owner's fallback for a ladder's parked offers may be (OF-305):
/// the wire its calls speak, whether its role's work stays on the device, and
/// how many rungs its seat's config names. A fallback answers as the rung
/// after those.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SeatScope {
    pub(super) wire: Wire,
    pub(super) stays_on_device: bool,
    pub(super) configured: usize,
}

/// What a call asks of a fallback (OF-305): the chat request as it is sent
/// and whether it streams, or the whole media request. A speech call in a
/// banked voice asks each rung for its live binding of the voice instead
/// (FIX 1746), and no fallback serves it.
#[derive(Clone, Copy)]
enum Needs<'a> {
    Chat {
        request: &'a LlmRequest,
        stream: bool,
    },
    Media(&'a MediaRequest),
    Voiced(&'a RungVoices),
}

/// What a call met on the ladder it fell back from (OF-305): how many rungs
/// went out and failed there, and each rung it passed over there. The
/// fallback's receipt counts and lists these first.
#[derive(Clone, Default)]
struct ReceiptPrefix {
    failed: usize,
    passed_over: Vec<JsonValue>,
}

/// The served receipt of one rung's answer, waiting for that answer's usage.
/// A job's receipt waits until the job ends, kept on its row so a restart
/// keeps it too.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PendingReceipt {
    provider: String,
    requested: String,
    rung: usize,
    failed: usize,
    passed_over: JsonValue,
}

impl PendingReceipt {
    /// The receipt, wrapped around the provider's own usage `raw_provider`.
    pub(super) fn stamp(&self, raw_provider: JsonValue) -> JsonValue {
        served_receipt(
            &self.provider,
            &self.requested,
            self.rung,
            self.failed,
            self.passed_over.clone(),
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

/// `request` as the rung `rung` would send it: under its model and where it
/// runs.
fn rung_request(rung: &LadderRung, request: &MediaRequest) -> MediaRequest {
    let mut bound = request.clone();
    bound.model = rung.model.clone();
    bound.envelope.locality = rung.offer.binding.locality;
    bound
}

/// Whether a media call names a voice, typed or as a raw `voice` param.
fn names_voice(request: &MediaRequest) -> bool {
    request.voice.is_some() || request.params.contains_key("voice")
}

/// Whether `rung`'s row serves `request` as the rung would send it.
fn serves_media(rung: &LadderRung, request: &MediaRequest) -> bool {
    rung.media
        .as_ref()
        .is_some_and(|media| media.row.admit_media(&rung_request(rung, request)).is_ok())
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
    /// What an owner's fallback for its parked offers may be.
    scope: SeatScope,
    /// What the call met on the ladder it fell back from, when this ladder
    /// is that fallback's call-local copy.
    prefix: ReceiptPrefix,
}

impl OfferLadder {
    pub(super) fn seat(name: ModelId, rungs: Vec<LadderRung>, rests: Arc<OfferCooldowns>) -> Self {
        Self {
            name,
            rungs,
            receipt: true,
            picked: false,
            rests,
            scope: SeatScope::default(),
            prefix: ReceiptPrefix::default(),
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
            scope: SeatScope::default(),
            prefix: ReceiptPrefix::default(),
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
            scope: SeatScope::default(),
            prefix: ReceiptPrefix::default(),
        }
    }

    /// This ladder, with what an owner's fallback for its parked offers may
    /// be.
    #[must_use]
    pub(super) fn scoped(mut self, scope: SeatScope) -> Self {
        self.scope = scope;
        self
    }

    /// The offers of the rungs that could serve `request` (FIX 3194): each
    /// rung whose row serves it that holds its banked voice, or for a stock
    /// or raw voice the first such rung alone, as the walk sends it.
    pub(super) fn media_retry(
        &self,
        request: &MediaRequest,
        voices: Option<&RungVoices>,
    ) -> RetryHint {
        let first = if names_voice(request) {
            self.rungs
                .iter()
                .position(|rung| serves_media(rung, request))
        } else {
            None
        };
        let offers = self
            .rungs
            .iter()
            .enumerate()
            .filter(|&(index, rung)| {
                serves_media(rung, request)
                    && match voices {
                        Some(voices) => voices.holds(&rung.model),
                        None => first.is_none_or(|first| first == index),
                    }
            })
            .map(|(_, rung)| (rung.offer.binding.clone(), rung.wire_model.clone()))
            .collect();
        RetryHint {
            offers,
            rests: Some(Arc::clone(&self.rests)),
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

    /// The route prompt this ladder's one picked rung puts first, when it is
    /// one picked model (the ladder [`Self::generate_exact_within`] takes):
    /// a step replay compares it with the prompt its capsule was answered
    /// under (FIX 3028). `None` for any other ladder.
    #[must_use]
    pub fn exact_prompt(&self) -> Option<Option<&str>> {
        match self.rungs.as_slice() {
            [rung] if self.picked => Some(rung.prompt.as_deref()),
            _ => None,
        }
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
            usage.raw_provider = self.served(index, walk).stamp(raw);
        }
        usage
    }

    /// The served receipt of an answer from the rung at `index`: the rungs
    /// that went out and failed before it and those it passed over, with any
    /// on the ladder this call fell back from listed first.
    fn served(&self, index: usize, walk: &Walk) -> PendingReceipt {
        let rung = &self.rungs[index];
        PendingReceipt {
            provider: rung.provider.clone(),
            requested: rung.wire_model.clone(),
            rung: rung.position,
            failed: self.prefix.failed + walk.went_out(),
            passed_over: JsonValue::Array(self.passed_over(walk)),
        }
    }

    /// Each rung this call passed over, here and on the ladder it fell back
    /// from, those first.
    fn passed_over(&self, walk: &Walk) -> Vec<JsonValue> {
        let mut passed_over = self.prefix.passed_over.clone();
        if let JsonValue::Array(rows) = walk.passed_over(&self.rungs) {
            passed_over.extend(rows);
        }
        passed_over
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

    /// Whether the call passes the rung at `index` without sending it: it
    /// does not hold the call's voice (FIX 1746), a fallback to it would
    /// take the work off the device and the call's world stays on it, its
    /// offer rests from an earlier refusal, or its offer is on probation
    /// with its one probation request out. The voice and the device come
    /// first, so a rung the call may not use is never one it waits for.
    fn passes_over(&self, call: Call<'_>, index: usize, walk: &mut Walk) -> bool {
        if self.voice_not_held(call, index) {
            walk.note(index, Passed::VoiceNotHeld);
            return true;
        }
        if self.kept_on_device(index, call.request) {
            self.hold(call, index, walk);
            return true;
        }
        let rung = &self.rungs[index];
        if let Some(rest) = self.rests.resting(&rung.offer.binding, &rung.wire_model) {
            walk.note(index, Passed::Resting { rest });
            return true;
        }
        let Some(seen) = self.rests.probing(&rung.offer.binding, &rung.wire_model) else {
            return false;
        };
        walk.note(index, Passed::ProbeInFlight { seen });
        true
    }

    /// The permit to send the rung at `index`, taken right before it goes
    /// out (OF-305). If its offer's health rest began after the walk judged
    /// it, the rung is passed as resting. If its one probation request is
    /// out, the rung is passed to the next. Neither counts as a strike, and
    /// the call goes on.
    fn probe(&self, index: usize, walk: &mut Walk) -> Option<ProbePermit> {
        let rung = &self.rungs[index];
        match self.rests.try_probe(&rung.offer.binding, &rung.wire_model) {
            Ok(probe) => Some(probe),
            Err(ProbeBlocked::Resting(rest)) => {
                walk.note(index, Passed::Resting { rest });
                None
            }
            Err(ProbeBlocked::Busy { seen }) => {
                walk.note(index, Passed::ProbeInFlight { seen });
                None
            }
        }
    }

    /// Each built rung's live health at its configured position, for the
    /// status route. Read-only.
    pub(super) fn health(&self) -> Vec<(usize, RungHealth)> {
        self.rungs
            .iter()
            .map(|rung| {
                let health = self
                    .rests
                    .offer_health(&rung.offer.binding, &rung.wire_model);
                (rung.position, health)
            })
            .collect()
    }

    /// Waits for `back`, asking `may_send` meanwhile. Returns what is left
    /// of the call's wait `budget`, in seconds, after the wait. Each wait
    /// spends at least a second, so a chain ends.
    async fn wait_back(
        &self,
        back: Back,
        budget: u64,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> u64 {
        let waited = self
            .rests
            .wait(back.wait, back.at, back.seen, may_send)
            .await;
        budget.saturating_sub(waited.as_secs().max(1))
    }

    /// Whether every rung of this ladder rests now.
    pub(super) fn rests_now(&self) -> bool {
        self.rungs.iter().all(|rung| {
            self.rests
                .resting(&rung.offer.binding, &rung.wire_model)
                .is_some()
        })
    }

    /// Whether this ladder can take, as the owner's fallback, a call from a
    /// ladder of `scope` that asks `needs` (OF-305). It must speak the same
    /// wire (for a media seat, the same operation). It must not take the work
    /// off the device when the calling role's work stays on it. And each rung
    /// must accept the call as it would send it: a chat call passes the
    /// backend's own checks (streaming, tools, images, audio and the rest,
    /// with no I/O), and a media call passes the row's. A speech call that
    /// names a voice takes no owner's fallback (FIX 1746): a banked voice
    /// goes only to the rungs of its own ladder that hold it, a stock or raw
    /// one stays on its first rung, and a fallback never clones a voice.
    fn can_serve(&self, scope: &SeatScope, needs: Needs<'_>) -> bool {
        if matches!(needs, Needs::Voiced(..))
            || matches!(needs, Needs::Media(request) if names_voice(request))
        {
            return false;
        }
        self.scope.wire == scope.wire
            && !self.rungs.is_empty()
            && self.rungs.iter().all(|rung| {
                if scope.stays_on_device && leaves_device(&rung.offer.binding) {
                    return false;
                }
                match needs {
                    Needs::Chat { request, stream } => rung
                        .offer
                        .backend
                        .preflight(&rung.bind(request.clone()), stream)
                        .is_ok(),
                    Needs::Media(request) => serves_media(rung, request),
                    Needs::Voiced(..) => false,
                }
            })
    }

    /// This ladder as a model that a parked offer's calls may fall back to,
    /// once the owner names it.
    pub(super) fn fallback_rung(self: &Arc<Self>) -> Option<FallbackRung> {
        Some(FallbackRung {
            provider: self.rungs.first()?.provider.clone(),
            model: self.name.clone(),
            ladder: Arc::downgrade(self),
        })
    }

    /// The call-local ladder that a call takes to the owner's fallback
    /// `target` once every rung here has parked (OF-305). It holds the
    /// target's rungs, under this ladder's receipt and scope, and carries
    /// what the call met here. The receipt of its answer names the fallback's
    /// provider and model as the rung after this seat's configured ones. It
    /// counts the rungs that failed here too, and lists the rungs passed over
    /// here first. The shared target ladder is never changed.
    fn fallback_call(&self, target: &OfferLadder, walk: &Walk) -> Arc<OfferLadder> {
        let rungs = target
            .rungs
            .iter()
            .cloned()
            .enumerate()
            .map(|(offset, mut rung)| {
                rung.position = self.scope.configured + offset;
                rung
            })
            .collect();
        Arc::new(OfferLadder {
            name: target.name.clone(),
            rungs,
            receipt: self.receipt,
            picked: false,
            rests: Arc::clone(&target.rests),
            scope: self.scope,
            prefix: ReceiptPrefix {
                failed: self.prefix.failed + walk.went_out(),
                passed_over: self.passed_over(walk),
            },
        })
    }

    /// Once every rung the call met has parked, the owner's question about
    /// each one parked on a spent window or spent credit (OF-305: asked only
    /// when no rung is left to serve the call). The models it lists for
    /// `use_fallback` are only those that can take this call from this seat.
    fn ask_parked(&self, walk: &Walk, needs: Needs<'_>) {
        let Some(parked) = walk.parked(self.rungs.len()) else {
            return;
        };
        let own: Vec<&str> = self
            .rungs
            .iter()
            .map(|rung| rung.provider.as_str())
            .collect();
        let fits = |fallback: &OfferLadder| fallback.can_serve(&self.scope, needs);
        for (index, rest) in parked {
            let rung = &self.rungs[index];
            let asked = Asked {
                provider: &rung.provider,
                wire_model: &rung.wire_model,
            };
            self.rests
                .ask(&rung.offer.binding, rest, asked, &own, &fits);
        }
    }

    /// Once every rung the call met has parked, the fallback the owner named
    /// for the first parked offer that has one (`use_fallback`). It applies
    /// while that model's offer is in rotation, while it can take this call
    /// from this seat ([`Self::can_serve`]), and while the call's world may
    /// go where it runs.
    fn fallback(&self, call: Call<'_>, walk: &Walk) -> Option<Arc<OfferLadder>> {
        walk.parked(self.rungs.len())?
            .into_iter()
            .find_map(|(index, _)| {
                let rung = &self.rungs[index];
                self.rests
                    .fallback_for(&rung.offer.binding, &rung.wire_model)
                    .filter(|fallback| !fallback.rests_now())
                    .filter(|fallback| fallback.can_serve(&self.scope, call.needs))
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

    /// Whether the call's voice keeps it from the rung at `index` (FIX 1746).
    /// A banked voice goes only to a rung whose target held a live binding
    /// of it when the call was admitted. A stock or raw voice is one
    /// provider's name, so it goes only to the first rung whose row serves
    /// the call: never to another provider, in another voice.
    fn voice_not_held(&self, call: Call<'_>, index: usize) -> bool {
        match call.needs {
            Needs::Voiced(voices) => !voices.holds(&self.rungs[index].model),
            Needs::Media(request) if names_voice(request) => {
                self.rungs
                    .iter()
                    .position(|rung| serves_media(rung, request))
                    != Some(index)
            }
            Needs::Media(_) | Needs::Chat { .. } => false,
        }
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
    /// the wait goes only to an offer the call may use now. A rung whose
    /// probation request was out ends the wait early when that request ends
    /// (OF-305). If only such a rung is left, the call waits for that end,
    /// for the rest of its budget.
    fn waits_for(&self, call: Call<'_>, walk: &mut Walk, budget_secs: u64) -> Option<Back> {
        if !walk.limited() {
            return None;
        }
        for index in 0..self.rungs.len() {
            if !self.voice_not_held(call, index) && self.kept_on_device(index, call.request) {
                self.hold(call, index, walk);
            }
        }
        let now = self.rests.now()?;
        let probing = walk.probing();
        let seen = probing.map(|(_, seen)| seen);
        if let Some((index, at)) = walk.back()
            && at.saturating_sub(now) <= budget_secs
        {
            return Some(Back {
                index,
                at,
                wait: Duration::from_secs(at.saturating_sub(now)),
                seen,
            });
        }
        let (index, seen) = probing.filter(|_| budget_secs > 0)?;
        Some(Back {
            index,
            at: now.saturating_add(budget_secs),
            wait: Duration::from_secs(budget_secs),
            seen: Some(seen),
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
    fn unanswered(&self, call: Call<'_>, walk: Walk) -> LlmError {
        self.ask_parked(&walk, call.needs);
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
            .map(|(response, _)| response)
    }

    /// [`Self::generate_exact_within`] waiting as [`Self::generate_while`]
    /// does, for the vault's longest wait: a call a durable seat bound,
    /// which its one model answers or nothing does.
    pub async fn generate_exact(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmResponse> {
        let budget = Duration::from_secs(self.rests.max_wait_secs());
        self.generate_exact_within(run, request, selector, &|| true, budget)
            .await
    }

    /// [`Self::generate_within`] for a caller that must know the model it
    /// named is the one that answered (an exact-model decision, OF-184):
    /// only a ladder that is one picked model takes the call, and no owner's
    /// fallback does. A seat's ladder refuses it as an invalid request.
    pub async fn generate_exact_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        if !self.picked || self.rungs.len() != 1 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.generate_from(run, request, selector, may_send, wait_budget, false)
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::generate`], with the model of the rung that answered, the
    /// owner's fallback included: the executor a caller stamps on the
    /// attempt it ran for (OF-540).
    pub async fn generate_served(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<(LlmResponse, ModelId)> {
        let budget = Duration::from_secs(self.rests.max_wait_secs());
        self.generate_from(run, request, selector, &|| true, budget, true)
            .await
    }

    /// [`Self::generate_within`], with the model of the rung that answered,
    /// the owner's fallback included: the model a decision's receipt names
    /// (FIX 2730), on the caller's own deadline.
    pub async fn generate_served_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<(LlmResponse, ModelId)> {
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
    ) -> ServedFuture<'a> {
        Box::pin(async move {
            self.walk_generate(run, request, selector, may_send, wait_budget, may_fall_back)
                .await
        })
    }

    async fn walk_generate(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
        may_fall_back: bool,
    ) -> LlmResult<(LlmResponse, ModelId)> {
        self.admits(&request)?;
        // The run is live until this call ends: the host stays awake for it.
        let _awake = oneiron_vault_contract::host_adapters::run_awake();
        let call = Call {
            run,
            request: &request,
            selector,
            needs: Needs::Chat {
                request: &request,
                stream: false,
            },
        };
        let mut walk = Walk::default();
        let mut budget = wait_budget.as_secs();
        // The chain, each rung at most once a pass; then, while only rests
        // stopped it, the owner's fallback, or a wait for its first offer
        // back and the chain again, until the waits would pass the call's
        // budget.
        for pass in 0.. {
            if pass > 0 {
                if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                    let fallback = self.fallback_call(&target, &walk);
                    let mut fell_request = request.clone();
                    fell_request.model = fallback.model().clone();
                    let fell = fallback
                        .generate_from(
                            run,
                            fell_request,
                            Some(selector.unwrap_or(self.name.as_str())),
                            may_send,
                            Duration::from_secs(budget),
                            false,
                        )
                        .await;
                    if fell.is_err() {
                        self.ask_parked(&walk, call.needs);
                    }
                    return fell;
                }
                let Some(back) = self
                    .waits_for(call, &mut walk, budget)
                    .filter(|_| may_send())
                else {
                    break;
                };
                budget = self.wait_back(back, budget, may_send).await;
            }
            let mut sent = vec![false; self.rungs.len()];
            loop {
                if !may_send() {
                    return Err(self.unanswered(call, walk));
                }
                let Some(index) = self.next_rung(call, &sent, &mut walk) else {
                    break;
                };
                sent[index] = true;
                match self.send(call, index, may_send, &mut walk).await? {
                    Sent::Answer(response) => {
                        return Ok((response, self.rungs[index].model.clone()));
                    }
                    Sent::Failed | Sent::Held => {}
                    Sent::Stopped => return Err(self.unanswered(call, walk)),
                }
            }
        }
        Err(self.unanswered(call, walk))
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
        let Some(_probe) = self.probe(index, walk) else {
            settle_failed(permit);
            return Ok(Sent::Held);
        };
        let gate = call
            .run
            .gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        match gate.generate(bound, permit.lease()).await {
            Ok(mut response) => {
                self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
                permit.settle(CallOutcome::Answered(&response.usage))?;
                response.usage = self.answered(index, walk, response.usage);
                rung.note_answered(call.request);
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
    /// waits for its first offer back. Once every rung has parked, a call
    /// whose parked offer has the owner's fallback goes there (OF-305). A job
    /// (`ai.video`) answers with its started permit held, to settle when the
    /// job ends.
    /// A speech call in a banked voice carries each rung's live binding of
    /// it in `voices`: it goes only to those rungs, each in its own binding
    /// (FIX 1746).
    pub(super) async fn media(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        selector: Option<&str>,
        voices: Option<&RungVoices>,
    ) -> LlmResult<MediaAnswer> {
        self.media_from(
            run,
            request,
            selector,
            self.rests.max_wait_secs(),
            true,
            voices,
        )
        .await
    }

    /// [`Self::media`], waiting for offers back for at most `budget_secs` in
    /// all. When `may_fall_back`, a call whose every rung has parked goes to
    /// the owner's fallback; a fallback's own call falls back no further.
    /// Boxed, since a fallback's call is this one again.
    fn media_from<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: MediaRequest,
        selector: Option<&'a str>,
        budget_secs: u64,
        may_fall_back: bool,
        voices: Option<&'a RungVoices>,
    ) -> MediaFuture<'a, MediaAnswer> {
        Box::pin(async move {
            let admission = request.admission_request();
            self.admits(&admission)?;
            let call = Call {
                run,
                request: &admission,
                selector,
                needs: match voices {
                    Some(voices) => Needs::Voiced(voices),
                    None => Needs::Media(&request),
                },
            };
            let mut walk = Walk::default();
            let mut budget = budget_secs;
            for pass in 0.. {
                if pass > 0 {
                    if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                        let fallback = self.fallback_call(&target, &walk);
                        let mut fell_request = request.clone();
                        fell_request.model = fallback.model().clone();
                        let fell = fallback
                            .media_from(
                                run,
                                fell_request,
                                Some(selector.unwrap_or(self.name.as_str())),
                                budget,
                                false,
                                voices,
                            )
                            .await;
                        if fell.is_err() {
                            self.ask_parked(&walk, call.needs);
                        }
                        return fell;
                    }
                    let Some(back) = self.waits_for(call, &mut walk, budget) else {
                        break;
                    };
                    budget = self.wait_back(back, budget, &|| true).await;
                }
                let mut sent = vec![false; self.rungs.len()];
                while let Some(index) = self.next_rung(call, &sent, &mut walk) {
                    sent[index] = true;
                    if let Some(answer) = self.send_media(call, index, &request, &mut walk).await? {
                        return Ok(answer);
                    }
                }
            }
            Err(self.unanswered(call, walk))
        })
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
        let mut bound = rung_request(rung, request);
        // A banked voice goes out in this rung's own binding of it, while
        // that is still current (FIX 1746).
        if let Needs::Voiced(voices) = call.needs {
            let Some(voice) = voices.send_on(&rung.model) else {
                walk.note(index, Passed::VoiceNotHeld);
                return Ok(None);
            };
            bound.voice = Some(voice);
        }
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
        let Some(probe) = self.probe(index, walk) else {
            settle_failed(permit);
            return Ok(None);
        };
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
                    probe: Some(probe),
                    receipt: self.receipt.then(|| self.served(index, walk)),
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
                    response.usage.raw_provider = self.served(index, walk).stamp(raw);
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
        self.stream_from(run, request, selector, true, self.rests.max_wait_secs())
    }

    /// [`Self::stream`], waiting for offers back for at most `budget_secs`
    /// in all. When `may_fall_back`, a stream whose every rung has parked,
    /// as it opens or after any pass, goes to the owner's fallback for a
    /// parked offer; a fallback's own stream falls back no further.
    fn stream_from(
        self: &Arc<Self>,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_fall_back: bool,
        budget_secs: u64,
    ) -> LlmResult<LlmStream<'static>> {
        self.admits(&request)?;
        let call = Call {
            run,
            request: &request,
            selector,
            needs: Needs::Chat {
                request: &request,
                stream: true,
            },
        };
        let mut walk = Walk::default();
        let (start, wait) =
            match (0..self.rungs.len()).find(|index| !self.passes_over(call, *index, &mut walk)) {
                Some(start) => (start, None),
                None => {
                    if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                        let fallback = self.fallback_call(&target, &walk);
                        let mut fell_request = request.clone();
                        fell_request.model = fallback.model().clone();
                        let selector = Some(selector.unwrap_or(self.name.as_str()));
                        let fell =
                            fallback.stream_from(run, fell_request, selector, false, budget_secs);
                        if fell.is_err() {
                            self.ask_parked(&walk, call.needs);
                        }
                        return fell;
                    }
                    match self.waits_for(call, &mut walk, budget_secs) {
                        Some(back) => (back.index, Some(back)),
                        None => return Err(self.unanswered(call, walk)),
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
            let sends = Sends {
                may_fall_back,
                budget_secs,
                events: &events,
            };
            ladder
                .stream_rungs(&run, &request, selector.as_deref(), opening, sends)
                .await;
        })))
    }

    async fn stream_rungs(
        &self,
        run: &RunAdmission,
        request: &LlmRequest,
        selector: Option<&str>,
        opening: Opening,
        sends: Sends<'_>,
    ) {
        let Opening {
            start,
            first,
            wait,
            mut walk,
        } = opening;
        let Sends {
            may_fall_back,
            budget_secs,
            events,
        } = sends;
        let call = Call {
            run,
            request,
            selector,
            needs: Needs::Chat {
                request,
                stream: true,
            },
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
                if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                    self.stream_fallback(&target, call, walk, budget_secs, events)
                        .await;
                    return;
                }
                let Some(back) = self.waits_for(call, &mut walk, budget_secs) else {
                    let _ = events.send(Err(self.unanswered(call, walk))).await;
                    return;
                };
                wait = Some(back);
            }
        }
        // The chain; then, while only rests stopped it, the owner's fallback
        // or a wait for its first offer back and the chain again, until the
        // waits would pass the call's wait budget in all (OF-305). A stream
        // that opened with every usable offer resting starts with that wait.
        let mut budget = budget_secs;
        let mut back = wait;
        loop {
            if let Some(next) = back {
                // Dropping the stream drops this wait: nothing else stops it.
                budget = self.wait_back(next, budget, &|| true).await;
            }
            if let Flow::Ended = self
                .stream_pass(run, request, selector, &mut held, &mut walk, events)
                .await
            {
                return;
            }
            if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                if let Some((_, (_, permit))) = held.take() {
                    settle_failed(permit);
                }
                self.stream_fallback(&target, call, walk, budget, events)
                    .await;
                return;
            }
            back = self.waits_for(call, &mut walk, budget);
            if back.is_none() {
                break;
            }
        }
        if let Some((_, (_, permit))) = held {
            settle_failed(permit);
        }
        let _ = events.send(Err(self.unanswered(call, walk))).await;
    }

    /// Hands a stream whose every rung has parked to the owner's fallback
    /// `target` (OF-305). Its call-local ladder streams the same request,
    /// under the caller's selector, into `events`, within what is left of
    /// the wait budget `budget_secs`, and falls back no further. Nothing has
    /// spoken yet, so its events are the answer. If the fallback refuses to
    /// open, the owner is asked about the offers parked here, and the
    /// refusal ends the stream.
    async fn stream_fallback(
        &self,
        target: &OfferLadder,
        call: Call<'_>,
        walk: Walk,
        budget_secs: u64,
        events: &Sender<LlmResult<LlmStreamEvent>>,
    ) {
        let fallback = self.fallback_call(target, &walk);
        let mut request = call.request.clone();
        request.model = fallback.model().clone();
        let selector = Some(call.selector.unwrap_or(self.name.as_str()));
        match fallback.stream_from(call.run, request, selector, false, budget_secs) {
            Ok(mut stream) => {
                while let Some(event) = stream.next().await {
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
            }
            Err(error) => {
                self.ask_parked(&walk, call.needs);
                let _ = events.send(Err(error)).await;
            }
        }
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
            needs: Needs::Chat {
                request,
                stream: true,
            },
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
        // Held until the stream ends, however it ends.
        let Some(_probe) = self.probe(index, walk) else {
            settle_failed(permit);
            return Flow::On;
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

/// One call on its way down the ladder: its run, its request, what the
/// caller named it by, and what it asks of an owner's fallback.
#[derive(Clone, Copy)]
struct Call<'a> {
    run: &'a RunAdmission,
    request: &'a LlmRequest,
    selector: Option<&'a str>,
    needs: Needs<'a>,
}

/// How a stream sends once it has opened: whether it may still go to the
/// owner's fallback, its wait budget, and where its events go.
struct Sends<'a> {
    may_fall_back: bool,
    budget_secs: u64,
    events: &'a Sender<LlmResult<LlmStreamEvent>>,
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
/// wait until then. If a rung's probation request was out, `seen` is the
/// health version it was seen at: that request's end cuts the wait short.
#[derive(Clone, Copy)]
struct Back {
    index: usize,
    at: u64,
    wait: Duration,
    seen: Option<u64>,
}

/// What sending one rung came to.
enum Sent {
    Answer(LlmResponse),
    /// It failed and the call goes on.
    Failed,
    /// It was kept from the work, unsent, and the call goes on. Either the
    /// world stays on the device, or its offer's health holds it.
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
            needs: Needs::Media(&request),
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
        Err(self.unanswered(call, walk))
    }
}
