//! Session transitions only. No audio scheduler, provider task or durable turn store.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::Vault;
use crate::error::Result;
use crate::interlocutor::InterlocutorResolutionInput;
use crate::policy_model::PolicyClassifyRequest;
use crate::speculative::SpeculativeSessionConfig;

use super::retrieval::invalid;
use super::{
    AsrEvent, AsrEventKind, BrainEvent, BrainRequest, ControlEvent, GenerationEpoch, OutputStop,
    PartialEnricher, PartialRetrieval, PcmFrame, SafeguardRequest, SentenceEnforcement,
    SentenceWork, SpeculativeRetrievalBridge, StopReason, ToolEvent, UtteranceHandle,
};

const MAX_TOOL_EVENTS: usize = 128;
const MAX_PENDING_SENTENCES: usize = 64;

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
}

struct Generation {
    request: BrainRequest,
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

    pub fn close_utterance(&mut self, handle: &UtteranceHandle) -> bool {
        self.retrieval.close_utterance(handle)
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
        match event.kind {
            AsrEventKind::Partial => self
                .retrieval
                .observe_partial(handle, revision, &event.text, enricher)
                .map(AsrUpdate::Partial),
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
                let interlocutors = self
                    .vault
                    .resolve_interlocutors(&self.config.interlocutors)?;
                let retrieval = self
                    .retrieval
                    .finalize(handle, revision, &event.text, enricher)?;
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
                    tool_events: Vec::new(),
                    externally_tainted,
                };
                self.generation = Some(Generation {
                    request: request.clone(),
                    llm_done: false,
                    audio_open: true,
                    sentence: 0,
                    pending_safeguards: BTreeSet::new(),
                });
                Ok(AsrUpdate::Final(request))
            }
            AsrEventKind::Endpoint => Ok(AsrUpdate::Endpoint),
            AsrEventKind::Error => {
                self.retrieval.close_utterance(handle);
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
            }
            BrainEvent::Error(_) => active.llm_done = true,
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
        if active.pending_safeguards.len() >= MAX_PENDING_SENTENCES {
            return Err(invalid("too many pending safeguard sentences"));
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
        let stop = halts.then(|| self.stop_generation(StopReason::Safeguard, cancel_llm));
        Some(SafeguardUpdate { control, stop })
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
        self.speech_latched = true;
        Ok(self
            .generation
            .is_some()
            .then(|| self.stop_generation(StopReason::UserBargeIn, true)))
    }

    /// Check at BOTH enqueue and dequeue in the audio sibling. This also accepts
    /// final TTS PCM after brain Done, until drain acknowledgement or cancellation.
    #[must_use]
    pub fn accepts_pcm(&self, generation: GenerationEpoch) -> bool {
        !self.ended
            && self.generation.as_ref().is_some_and(|active| {
                active.audio_open
                    && active.request.generation == generation
                    && generation.value == self.epoch
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
        Ok(true)
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

    fn stop_generation(&mut self, reason: StopReason, cancel_llm: bool) -> OutputStop {
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
    if !request.tools_enabled || request.tool_events.len() >= MAX_TOOL_EVENTS {
        return Err(invalid("tools disabled or ephemeral tool context full"));
    }
    match event {
        ToolEvent::Call {
            call_id,
            name,
            input,
        } => {
            let calls = request
                .tool_events
                .iter()
                .filter(|event| matches!(event, ToolEvent::Call { .. }))
                .count();
            if calls >= MAX_TOOL_EVENTS / 2 {
                return Err(invalid("tool context must reserve room for every result"));
            }
            if call_id.trim().is_empty() || name.trim().is_empty() || !input.is_object()
                || request.tool_events.iter().any(|event| {
                    matches!(event, ToolEvent::Call { call_id: prior, .. } if prior == call_id)
                })
            {
                return Err(invalid("tool call needs a unique id, name and object input"));
            }
        }
        ToolEvent::Result { call_id, output } => {
            let called = request.tool_events.iter().any(
                |event| matches!(event, ToolEvent::Call { call_id: prior, .. } if prior == call_id),
            );
            let returned = request.tool_events.iter().any(|event| {
                matches!(event, ToolEvent::Result { call_id: prior, .. } if prior == call_id)
            });
            if !called || returned || !output.is_object() {
                return Err(invalid(
                    "tool result needs one prior call and object output",
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
