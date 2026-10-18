//! Session transitions only. No audio scheduler, provider task or durable turn store.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::conversation::OutputMark;
use crate::error::{Error, Result};
use crate::interlocutor::{InterlocutorResolutionInput, InterlocutorSet};
use crate::policy_model::PolicyClassifyRequest;
use crate::speculative::SpeculativeSessionConfig;
use crate::store::GateSystemNoticeRecord;
use crate::{EdgeActorClass, EntityId, Vault};

use super::retrieval::invalid;
use super::{
    AsrEvent, AsrEventKind, BrainEvent, BrainRequest, ControlEvent, GenerationEpoch, OutputStop,
    PartialEnricher, PartialRetrieval, PcmFrame, SafeguardRequest, SentenceEnforcement,
    SentenceWork, SpeculativeRetrievalBridge, StopReason, ToolEvent, UtteranceHandle,
};

#[path = "preparation.rs"]
mod preparation;
pub use preparation::PreparedAsr;

/// How long a bound session's "who is this?" ask for a speaker it could
/// not place stays open: the ask door's own default for an ask with no
/// class (CALLS.md: FIX 1388 ask expiry).
pub const VOICE_IDENTITY_ASK_SECONDS: u64 = 24 * 60 * 60;

/// A voice session's trusted binding to the committed container it is
/// heard in (OF-365 P5). Only the host's auth layer supplies it, never a
/// voice match, the wire or a spoken claim, and the session never parses
/// its roster ref as a room id.
#[derive(Debug, Clone)]
pub struct VoiceContainerBinding {
    /// The conversation (chat, room or meeting) the session is heard in.
    pub container: EntityId,
    /// The verified writer each speaker's entry is recorded by: the
    /// session's authenticated person.
    pub writer: EntityId,
    pub writer_class: EdgeActorClass,
    /// Live contacts an unplaced speaker may be, in the host's order.
    pub candidates: Vec<EntityId>,
    /// How long each "who is this?" ask stays open, in engine seconds.
    pub ask_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct VoiceSessionConfig {
    /// Host session/off-record correlation, not permission to persist a turn.
    pub session_ref: String,
    /// Supplied only by the host auth layer. Never derive `owner_session` from
    /// provider tokens, voice matches or spoken claims. Existing roster/identity
    /// resolution is re-read at each final, not copied into another identity DB.
    pub interlocutors: InterlocutorResolutionInput,
    pub tools_enabled: bool,
    /// Must be within 100–150 ms. Default 120 ms.
    pub barge_in_hold: Duration,
    pub policy_world_ref: Option<String>,
    pub policy_caller_ref: Option<String>,
    /// The person this session is with, proved by the host auth layer, never
    /// by a voice match or a spoken claim. A sentence the policy gate routes
    /// to help reaches this person's trusted contacts (OF-527); without it,
    /// it reaches no one's.
    pub policy_person: Option<crate::consent::AuthenticatedOwner>,
    /// The container this session is heard in, when its host bound one.
    /// Each speaker it cannot place enters it before any context is
    /// assembled, and an attendee's entry stops output assembled before
    /// it. Without one, the session is no room's.
    pub container: Option<VoiceContainerBinding>,
}

impl VoiceSessionConfig {
    #[must_use]
    pub fn new(session_ref: impl Into<String>, interlocutors: InterlocutorResolutionInput) -> Self {
        Self {
            session_ref: session_ref.into(),
            interlocutors,
            tools_enabled: false,
            barge_in_hold: Duration::from_millis(120),
            policy_world_ref: None,
            policy_caller_ref: None,
            policy_person: None,
            container: None,
        }
    }
}

#[must_use = "forward the accepted ASR update; start the brain only on Final"]
#[derive(Debug)]
pub enum AsrUpdate {
    Ignored,
    Partial(PartialRetrieval),
    /// Start the text brain and TTS generation with this epoch. Retrieval is
    /// already final/promoted. No provider call may run under the session lock.
    Final(BrainRequest),
    Endpoint,
    Error(String),
    Closed(OutputStop),
}

#[must_use = "deliver backend status and dispatch any output stop before playback"]
#[derive(Debug)]
pub struct SafeguardUpdate {
    pub control: ControlEvent,
    pub stop: Option<OutputStop>,
    /// The gate's notices to the person and the model, among them what a
    /// `RouteToHelp` did for the person's trusted contacts. The host says
    /// each one to both; none is silent.
    pub notices: Vec<GateSystemNoticeRecord>,
}

/// What a roster refresh found (OF-365 P5). Dispatch `stop` before another
/// playback dequeue, then assemble the brain's context afresh for
/// `audience_revision`. The stopped utterance is not re-run on its own.
#[must_use = "dispatch any output stop, then assemble context for the new audience revision"]
#[derive(Debug)]
pub struct AudienceRefresh {
    pub audience_revision: u64,
    /// Whether the audience differs from the one last read.
    pub changed: bool,
    /// The audience now; `None` when it could not be read, which counts as
    /// a change.
    pub interlocutors: Option<InterlocutorSet>,
    pub stop: Option<OutputStop>,
}

struct Generation {
    budget: Option<super::budget::GenerationBudget>,
    request: BrainRequest,
    /// Taken before this generation's audience was read: its audio goes
    /// out only while no attendee has entered the bound container since.
    mark: OutputMark,
    llm_done: bool,
    audio_open: bool,
    sentence: u64,
    pending_safeguards: BTreeSet<u64>,
}

pub struct VoiceCascadeSession {
    vault: Arc<Vault>,
    config: VoiceSessionConfig,
    retrieval: SpeculativeRetrievalBridge,
    id: uuid::Uuid,
    epoch: u64,
    generation: Option<Generation>,
    ended: bool,
    speech_started: Option<Duration>,
    speech_latched: bool,
    last_speech_observation: Option<Duration>,
    preparation_serial: u64,
    prepared_asr: Option<PreparedAsr>,
    preparation_active: bool,
    /// The audience last read, at a final or a roster refresh.
    audience: Option<InterlocutorSet>,
    /// Moves on every audience change; a brain request and a prepared ASR
    /// attempt carry the revision they were made at.
    audience_revision: u64,
}

impl VoiceCascadeSession {
    pub fn new(vault: Arc<Vault>, config: VoiceSessionConfig) -> Result<Self> {
        if config.session_ref.trim().is_empty()
            || !(Duration::from_millis(100)..=Duration::from_millis(150))
                .contains(&config.barge_in_hold)
        {
            return Err(invalid(
                "session ref must be nonempty and barge-in hold must be 100–150 ms",
            ));
        }
        Ok(Self {
            retrieval: SpeculativeRetrievalBridge::new(Arc::clone(&vault)),
            vault,
            config,
            id: uuid::Uuid::new_v4(),
            epoch: 0,
            generation: None,
            ended: false,
            speech_started: None,
            speech_latched: false,
            last_speech_observation: None,
            preparation_serial: 0,
            prepared_asr: None,
            preparation_active: false,
            audience: None,
            audience_revision: 0,
        })
    }

    /// May open while the assistant speaks: incoming partial retrieval and
    /// sustained speech detection run alongside the previous output generation.
    pub fn open_utterance(
        &mut self,
        utterance_id: impl Into<String>,
        config: SpeculativeSessionConfig,
    ) -> Result<UtteranceHandle> {
        self.require_open()?;
        self.retrieval.open_utterance(utterance_id, config)
    }

    /// Whether this exact utterance is still live, including after a failed final.
    #[must_use]
    pub fn is_utterance_open(&self, handle: &UtteranceHandle) -> bool {
        !self.ended && self.retrieval.is_open(handle)
    }

    pub fn close_utterance(&mut self, handle: &UtteranceHandle) -> bool {
        let closed = self.retrieval.close_utterance(handle);
        if closed {
            self.prepared_asr = None;
            self.preparation_active = false;
        }
        closed
    }

    /// `externally_tainted` is a trusted host mark on the assembled FINAL
    /// context, not an ASR-provider claim. Later tool/context taint only adds to it.
    /// Revisions advance on partial/final, not on endpoint metadata. Stale handle
    /// events (including old close/error callbacks) have no effect.
    pub fn handle_asr(
        &mut self,
        handle: &UtteranceHandle,
        revision: u64,
        event: AsrEvent,
        externally_tainted: bool,
        enricher: &mut impl PartialEnricher,
    ) -> Result<AsrUpdate> {
        if self.ended || !self.retrieval.is_open(handle) {
            return Ok(AsrUpdate::Ignored);
        }
        event.validate()?;
        if matches!(event.kind, AsrEventKind::Partial | AsrEventKind::Final) {
            self.retrieval.check_revision(handle, revision)?;
            self.check_prepared_revision(handle, revision, &event, externally_tainted)?;
            if event.kind == AsrEventKind::Final && self.generation.is_some() {
                return Err(invalid(
                    "finish or interrupt the previous generation before final",
                ));
            }
            // Retire the attempt, but keep its exact-input fence until the
            // revision is consumed or the utterance is closed.
            self.preparation_active = false;
        }
        match event.kind {
            AsrEventKind::Partial => {
                let retrieval =
                    self.retrieval
                        .observe_partial(handle, revision, &event.text, enricher)?;
                self.prepared_asr = None;
                Ok(AsrUpdate::Partial(retrieval))
            }
            AsrEventKind::Final => {
                // Do not consume a final while a generation is still live. The
                // host must first barge in, or acknowledge normal drained output.
                // This refuses silent turn replacement mislabeled as barge-in.
                if self.generation.is_some() {
                    return Err(invalid(
                        "finish or interrupt the previous generation before final",
                    ));
                }
                let next = self
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("generation epoch exhausted"))?;
                // The mark follows this final's own entries, which its
                // audience reads, and precedes that read.
                self.enter_bound_speakers();
                let mark = self.vault.container_output_mark();
                let interlocutors = self.resolve_audience()?;
                self.observe_audience(Some(&interlocutors))?;
                let retrieval = self
                    .retrieval
                    .finalize(handle, revision, &event.text, enricher);
                // Final retrieval can fail after closing the utterance. That
                // lifecycle invalidation also releases the fence; earlier
                // identity/enrichment failures must leave it intact for retry.
                if !self.retrieval.is_open(handle) {
                    self.prepared_asr = None;
                }
                let retrieval = retrieval?;
                self.epoch = next;
                let request = BrainRequest {
                    generation: GenerationEpoch {
                        session: self.id,
                        value: next,
                    },
                    transcript: event.text,
                    retrieval,
                    session_ref: self.config.session_ref.clone(),
                    tools_enabled: self.config.tools_enabled,
                    interlocutors,
                    audience_revision: self.audience_revision,
                    tool_events: Vec::new(),
                    externally_tainted,
                };
                self.generation = Some(Generation {
                    budget: None,
                    request: request.clone(),
                    mark,
                    llm_done: false,
                    audio_open: true,
                    sentence: 0,
                    pending_safeguards: BTreeSet::new(),
                });
                Ok(AsrUpdate::Final(request))
            }
            AsrEventKind::Endpoint => Ok(AsrUpdate::Endpoint),
            AsrEventKind::Error => {
                self.close_utterance(handle);
                Ok(AsrUpdate::Error(event.error.unwrap_or(event.text)))
            }
            AsrEventKind::Closed => Ok(AsrUpdate::Closed(self.end())),
        }
    }

    /// Accepted tool calls/results are stored in exact arrival order in the
    /// brain context. After `Some(Tool(..))`, pass `brain_context` to
    /// `Brain::update_context` BEFORE resuming the model. No tool is executed here.
    /// Host-side tool results use the same door; a result must have one prior
    /// call, and may appear only once. Done requires all tool results first.
    /// Complete any buffered trailing sentence BEFORE reporting Done.
    pub fn handle_brain(
        &mut self,
        generation: GenerationEpoch,
        event: BrainEvent,
        externally_tainted: bool,
    ) -> Result<Option<BrainEvent>> {
        let Some(active) = self.generation.as_mut().filter(|active| {
            active.request.generation == generation && !active.llm_done && !self.ended
        }) else {
            return Ok(None);
        };
        match &event {
            BrainEvent::Tool(tool) => {
                validate_tool(&active.request, tool)?;
                active.request.tool_events.push(tool.clone());
            }
            BrainEvent::Done => {
                if outstanding_tools(&active.request) {
                    return Err(invalid("brain done before tool results"));
                }
                active.llm_done = true;
                active.budget.take();
            }
            BrainEvent::Error(_) => {
                active.llm_done = true;
                active.budget.take();
            }
            BrainEvent::TextDelta(_) => {}
        }
        active.request.externally_tainted |= externally_tainted;
        // cancel_llm=false allows backend/tool context to drain, NEVER old
        // output. It does not retag old LLM events with the new audio epoch.
        if matches!(&event, BrainEvent::TextDelta(_)) && !active.audio_open {
            Ok(None)
        } else {
            Ok(Some(event))
        }
    }

    /// Reserve for the active generation before starting its backend. The session
    /// retains the issuing guard, so barge-in cannot settle against a foreign meter.
    pub fn reserve_generation_budget(
        &mut self,
        generation: GenerationEpoch,
        guard: Arc<crate::llm::BudgetGuard>,
        request: &crate::llm::LlmRequest,
    ) -> Result<crate::llm::BudgetLease> {
        let active = self
            .generation
            .as_mut()
            .filter(|active| active.request.generation == generation && !active.llm_done)
            .ok_or_else(|| invalid("generation is not active"))?;
        if active.budget.is_some() {
            return Err(invalid("generation already has a budget lease"));
        }
        let admission = guard
            .admit_for_request(request)
            .inspect_err(|denied| {
                self.vault
                    .budget_denied_hooks(denied, &guard, request.model.as_str(), None);
            })
            .map_err(|_| invalid("voice budget admission denied"))?;
        let lease = admission.lease;
        active.budget = Some(super::budget::GenerationBudget {
            guard,
            lease: lease.clone(),
            usage: crate::llm::LlmUsage::zero(),
        });
        Ok(lease)
    }

    /// Absolute per-generation provider usage, including partial spend on cancel.
    pub fn observe_generation_usage(
        &mut self,
        generation: GenerationEpoch,
        usage: crate::llm::LlmUsage,
    ) -> Result<bool> {
        let Some(budget) = self
            .generation
            .as_mut()
            .filter(|active| active.request.generation == generation)
            .and_then(|active| active.budget.as_mut())
        else {
            return Ok(false);
        };
        if usage.input.total < budget.usage.input.total
            || usage.output.total < budget.usage.output.total
        {
            return Err(invalid("voice usage cannot regress"));
        }
        budget.usage = usage;
        Ok(true)
    }

    #[must_use]
    pub fn brain_context(&self, generation: GenerationEpoch) -> Option<&BrainRequest> {
        self.generation
            .as_ref()
            .filter(|active| !self.ended && active.request.generation == generation)
            .map(|active| &active.request)
    }

    /// Use when the host adds external context outside a tool event. Taint is
    /// monotonic for the generation; provider content cannot clear it.
    pub fn taint_context(&mut self, generation: GenerationEpoch) -> bool {
        if let Some(active) = self
            .generation
            .as_mut()
            .filter(|active| !self.ended && active.request.generation == generation)
        {
            active.request.externally_tainted = true;
            true
        } else {
            false
        }
    }

    /// Sentence boundaries belong to the audio/text host, not a second parser
    /// here. TTS and safeguard share exactly the same completed sentence bytes.
    pub fn complete_sentence(
        &mut self,
        generation: GenerationEpoch,
        text: String,
    ) -> Result<Option<SentenceWork>> {
        if !self.accepts_pcm(generation) {
            return Ok(None);
        }
        let active = self
            .generation
            .as_mut()
            .ok_or_else(|| invalid("no active generation"))?;
        if active.llm_done || text.trim().is_empty() {
            return Err(invalid("sentence must be nonempty and precede brain done"));
        }
        active.sentence = active
            .sentence
            .checked_add(1)
            .ok_or_else(|| invalid("sentence id exhausted"))?;
        let safeguard = if active.request.externally_tainted {
            active.pending_safeguards.insert(active.sentence);
            Some(SafeguardRequest {
                vault: Arc::clone(&self.vault),
                generation,
                sentence: active.sentence,
                request: PolicyClassifyRequest {
                    world_ref: self.config.policy_world_ref.clone(),
                    caller_ref: self.config.policy_caller_ref.clone(),
                    concerned_person: self.config.policy_person.clone(),
                    ..PolicyClassifyRequest::outbound_content(text.clone())
                },
            })
        } else {
            None
        };
        Ok(Some(SentenceWork {
            generation,
            text,
            safeguard,
        }))
    }

    /// A block always closes TTS/queued PCM/client playout. Missing or inconsistent
    /// audio flags cannot weaken that invariant. The engine kill's `cancel_llm`
    /// is respected; without a kill record, a halt conservatively cancels it too.
    /// No warning/persona content is substituted for the original sentence.
    /// A stale result returns `None`; its notices are still on
    /// [`SentenceEnforcement::enforcement`], for the host to say before it
    /// drops it.
    pub fn apply_safeguard(&mut self, outcome: SentenceEnforcement) -> Option<SafeguardUpdate> {
        let active = self.generation.as_mut()?;
        if self.ended
            || active.request.generation != outcome.generation
            || !active.pending_safeguards.remove(&outcome.sentence)
        {
            return None;
        }
        let enforcement = outcome.enforcement;
        let halts = enforcement.action.halts()
            || enforcement.outbound_halted
            || enforcement.pre_display_block;
        let cancel_llm = enforcement
            .barge_in_kill
            .as_ref()
            .is_none_or(|kill| kill.cancel_llm);
        let control = ControlEvent::Safeguard {
            generation: outcome.generation,
            action: enforcement.action,
            receipt_ref: enforcement.receipt_ref,
            custom_tier_skipped: enforcement.custom_tier_skipped,
        };
        let notices = enforcement
            .system_notices
            .into_iter()
            .filter(|notice| notice.audience == "user_and_model")
            .collect();
        let stop = halts.then(|| self.stop_generation(StopReason::Safeguard, cancel_llm));
        Some(SafeguardUpdate {
            control,
            stop,
            notices,
        })
    }

    /// Feed monotonic host VAD observations. `speaking=true` asserts continuous
    /// speech since the previous observation; ANY silence resets the hold.
    /// Sparse partial text or endpoint timing is never used as a speech clock.
    /// One interruption per continuous speech interval; backward time is refused.
    pub fn observe_speech(&mut self, now: Duration, speaking: bool) -> Result<Option<OutputStop>> {
        self.require_open()?;
        if self.last_speech_observation.is_some_and(|last| now < last) {
            return Err(invalid("speech observation time moved backwards"));
        }
        self.last_speech_observation = Some(now);
        if !speaking {
            self.speech_started = None;
            self.speech_latched = false;
            return Ok(None);
        }
        let started = *self.speech_started.get_or_insert(now);
        if self.speech_latched || now - started < self.config.barge_in_hold {
            return Ok(None);
        }
        if self.generation.is_none() {
            return Ok(None);
        }
        let stop = self.stop_generation(StopReason::UserBargeIn, true);
        // Idle speech does not spend this interval's interruption. A final may
        // start output while the same continuous speech is still in progress.
        self.speech_latched = true;
        Ok(Some(stop))
    }

    /// Check at BOTH enqueue and dequeue in the audio sibling. This also accepts
    /// final TTS PCM after brain Done, until drain acknowledgement or cancellation.
    /// In a bound session, audio also stops going out the moment an
    /// attendee enters the container, before the entry's wake arrives.
    #[must_use]
    pub fn accepts_pcm(&self, generation: GenerationEpoch) -> bool {
        !self.ended
            && self.generation.as_ref().is_some_and(|active| {
                active.audio_open
                    && active.request.generation == generation
                    && generation.value == self.epoch
                    && self.config.container.as_ref().is_none_or(|bound| {
                        self.vault
                            .container_output_admits(active.mark, bound.container)
                    })
            })
    }

    #[must_use]
    pub fn filter_pcm(&self, frame: PcmFrame) -> Option<PcmFrame> {
        self.accepts_pcm(frame.generation).then_some(frame)
    }

    /// Normal response completion: the host acknowledges TTS end AND drained
    /// server/client output. Pending verdicts must still be able to stop playback,
    /// so neither Done nor an early drain acknowledgement drops the generation.
    pub fn finish_playout(&mut self, generation: GenerationEpoch) -> Result<bool> {
        let Some(active) = self
            .generation
            .as_ref()
            .filter(|active| active.request.generation == generation)
        else {
            return Ok(false);
        };
        if !active.llm_done || !active.pending_safeguards.is_empty() {
            return Err(invalid(
                "brain or safeguard still pending at playout finish",
            ));
        }
        self.generation = None;
        self.prepared_asr = None;
        self.preparation_active = false;
        Ok(true)
    }

    /// The host could not carry `generation`'s output on: a sentence was not
    /// spoken, its safeguard did not run, or a brain event was refused. A
    /// generation left live there would refuse the next final, and a gap in
    /// its speech would play as if nothing were missing. Dispatch the stop
    /// before another playback dequeue. `None` for a stale generation.
    pub fn fail_output(&mut self, generation: GenerationEpoch) -> Option<OutputStop> {
        (!self.ended
            && self
                .generation
                .as_ref()
                .is_some_and(|active| active.request.generation == generation))
        .then(|| self.stop_generation(StopReason::OutputFailed, true))
    }

    /// Explicit normal end/disconnect. The host also ends ASR and drops its task,
    /// PCM and provider queues. This sends SessionEnded, never a fake barge-in.
    /// Repeated calls are harmless and still permit retrying SessionEnded delivery.
    pub fn end(&mut self) -> OutputStop {
        let stop = self.stop_generation(StopReason::SessionEnd, true);
        self.ended = true;
        self.retrieval.close();
        self.speech_started = None;
        self.speech_latched = false;
        self.last_speech_observation = None;
        stop
    }

    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// Re-reads the session's interlocutors, for a host told the voice roster
    /// changed: someone joined, a speaker was placed differently, or the
    /// owner named one. An audience that differs from the one last read
    /// moves the audience revision, which fences prepared ASR, and stops a
    /// live generation, whose words were assembled for the old audience. An
    /// audience that cannot be read counts as changed. Labels and scores
    /// alone change nothing, and silence removes no one: the roster keeps
    /// every speaker it heard until the session ends.
    pub fn refresh_interlocutors(&mut self) -> Result<AudienceRefresh> {
        self.require_open()?;
        let interlocutors = self.read_audience().ok();
        let changed = self.observe_audience(interlocutors.as_ref())?;
        let stop = (changed && self.generation.is_some())
            .then(|| self.stop_generation(StopReason::RosterChanged, true));
        Ok(AudienceRefresh {
            audience_revision: self.audience_revision,
            changed,
            interlocutors,
            stop,
        })
    }

    /// The newcomer barrier (OF-365 P5, FIX 1389), for a host woken by an
    /// attendee's entry into the container this session is bound to.
    /// Everything assembled before the entry was assembled for an audience
    /// without the newcomer, so the audience revision moves even when the
    /// parties read the same: prepared ASR is fenced, and the brain rebuilds
    /// its history and retrieval for the new revision. A live generation
    /// stops before the next audio plays. Nothing re-runs on its own.
    pub fn entry_barrier(&mut self) -> Result<AudienceRefresh> {
        self.require_open()?;
        let interlocutors = self.read_audience().ok();
        if !self.observe_audience(interlocutors.as_ref())? {
            self.move_audience_revision()?;
        }
        self.prepared_asr = None;
        self.preparation_active = false;
        let stop = self
            .generation
            .is_some()
            .then(|| self.stop_generation(StopReason::RosterChanged, true));
        Ok(AudienceRefresh {
            audience_revision: self.audience_revision,
            changed: true,
            interlocutors,
            stop,
        })
    }

    /// Whether the audience last read already names the entry `entry_ref`:
    /// one this session recorded and read before its wake arrived, so no
    /// output was assembled without it.
    #[must_use]
    pub fn audience_names_entry(&self, entry_ref: EntityId) -> bool {
        self.audience.as_ref().is_some_and(|audience| {
            audience
                .non_owner()
                .any(|party| party.audience_ref() == Some(entry_ref))
        })
    }

    /// The session's audience now, after a bound session records the entry
    /// of each speaker its roster could not place.
    fn read_audience(&self) -> Result<InterlocutorSet> {
        self.enter_bound_speakers();
        self.resolve_audience()
    }

    /// A bound session reads each unplaced speaker through its entry, and
    /// one whose entry could not be recorded has none, so it narrows to
    /// nothing.
    fn resolve_audience(&self) -> Result<InterlocutorSet> {
        match &self.config.container {
            Some(bound) => self
                .vault
                .resolve_interlocutors_in_container(&self.config.interlocutors, bound.container),
            None => self.vault.resolve_interlocutors(&self.config.interlocutors),
        }
    }

    fn enter_bound_speakers(&self) {
        if let Some(bound) = &self.config.container
            && let Err(error) = self.enter_unplaced_speakers(bound)
        {
            tracing::warn!(%error, "voice: a speaker's entry was not recorded");
        }
    }

    /// Each speaker the session's stored roster could not place enters the
    /// bound container, keyed by the capture's speaker key under the
    /// roster's revision, and its owner is asked who it is, once. A speaker
    /// already entered replays its entry.
    fn enter_unplaced_speakers(&self, bound: &VoiceContainerBinding) -> Result<()> {
        let Some(roster_ref) = self.config.interlocutors.voice_session_ref.as_deref() else {
            return Ok(());
        };
        let Some(roster) = self.vault.voice_session_roster(roster_ref)? else {
            return Ok(());
        };
        if roster.unplaced_speakers().is_empty() {
            return Ok(());
        }
        let until = self
            .vault
            .now_recorded_at()
            .checked_add(bound.ask_seconds)
            .ok_or_else(|| invalid("voice identity ask expiry overflow"))?;
        self.vault
            .memory(bound.writer, bound.writer_class)
            .voice_speakers_entered(bound.container, &roster, None, &bound.candidates, until)
            .map(drop)
            .map_err(|error| Error::InvalidConfig(format!("voice speaker entry: {error}")))
    }

    /// Records the audience just read (`None`: unreadable), moving the
    /// revision when it differs from the last one read. The first read moves
    /// nothing: no output was assembled for an earlier audience.
    fn observe_audience(&mut self, audience: Option<&InterlocutorSet>) -> Result<bool> {
        let changed = match (&self.audience, audience) {
            (Some(prior), Some(audience)) => !prior.same_audience(audience),
            (None, Some(_)) => false,
            (_, None) => true,
        };
        if changed {
            self.move_audience_revision()?;
        }
        self.audience = audience.cloned();
        Ok(changed)
    }

    fn move_audience_revision(&mut self) -> Result<()> {
        self.audience_revision = self
            .audience_revision
            .checked_add(1)
            .ok_or_else(|| invalid("audience revision exhausted"))?;
        Ok(())
    }

    fn stop_generation(&mut self, reason: StopReason, cancel_llm: bool) -> OutputStop {
        self.prepared_asr = None;
        self.preparation_active = false;
        let generation = self
            .generation
            .as_ref()
            .map(|active| active.request.generation);
        if generation.is_some() {
            // Saturation never reuses a token: output is closed below and new
            // generations require checked_add. At exhaustion the next start fails.
            self.epoch = self.epoch.saturating_add(1);
        }
        if cancel_llm {
            self.generation = None;
        } else if let Some(active) = self.generation.as_mut() {
            active.audio_open = false;
            active.pending_safeguards.clear();
        }
        OutputStop::new(generation, reason, cancel_llm)
    }

    fn require_open(&self) -> Result<()> {
        if self.ended {
            Err(invalid("voice session ended"))
        } else {
            Ok(())
        }
    }
}

fn validate_tool(request: &BrainRequest, event: &ToolEvent) -> Result<()> {
    // Rule 5: a turn's tool context takes every call and result its brain
    // makes; no count refuses one. Its spend meter bounds the turn.
    if !request.tools_enabled {
        return Err(invalid("tools disabled"));
    }
    match event {
        ToolEvent::Call {
            call_id,
            name,
            input,
        } => {
            if call_id.trim().is_empty() || name.trim().is_empty() || !input.is_object()
                || request.tool_events.iter().any(|event| {
                    matches!(event, ToolEvent::Call { call_id: prior, .. } if prior == call_id)
                })
            {
                return Err(invalid("tool call needs a unique id, name and object input"));
            }
        }
        ToolEvent::Result { call_id, .. } => {
            let called = request.tool_events.iter().any(
                |event| matches!(event, ToolEvent::Call { call_id: prior, .. } if prior == call_id),
            );
            let returned = request.tool_events.iter().any(|event| {
                matches!(event, ToolEvent::Result { call_id: prior, .. } if prior == call_id)
            });
            if !called || returned {
                return Err(invalid(
                    "tool result needs one prior call and no prior result",
                ));
            }
        }
    }
    Ok(())
}

fn outstanding_tools(request: &BrainRequest) -> bool {
    let calls = request
        .tool_events
        .iter()
        .filter(|event| matches!(event, ToolEvent::Call { .. }))
        .count();
    calls * 2 != request.tool_events.len()
}
