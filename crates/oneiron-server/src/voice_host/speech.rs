//! The brain's reply in the host's own voice (OF-410). The owner's brain
//! hands its events back as [`VoiceBrainOut`], and each one passes the
//! session's `handle_brain` first. Its text is cut into sentences on the
//! session's cadence, and each sentence passes `complete_sentence` before it
//! is spoken: the TTS seam and the sentence's safeguard get the same bytes at
//! once, and the verdict comes back through `apply_safeguard`, which can
//! still stop the audio it outran. Spoken audio reaches the owner's playout
//! as a [`PlayoutFrame`] that reads the session again when it is dequeued,
//! and a generation's last audio is marked with [`VoicePlayout::End`]. The
//! owner's [`VoiceMediaIn::Drained`](super::VoiceMediaIn::Drained) for it
//! closes the generation through `finish_playout` once its brain and every
//! verdict are done. A sentence that was not spoken, a safeguard that did
//! not run and a brain event the session refused stop the generation
//! (`StopReason::OutputFailed`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use oneiron::llm::{BudgetGuard, LlmBackend, LlmStreamEvent, VoiceChunkPolicy, VoiceChunker};
use oneiron::policy_model::PolicyModelConfig;
use oneiron::voice_cascade::{
    Brain, BrainEvent, CascadeControl, ControlEvent, GenerationEpoch, OutputStop, PcmFrame,
    Safeguard, SafeguardRequest, SentenceEnforcement, TtsCommand, TtsSeamClient,
};

use super::media_bridge::MediaBridge;
use super::{HostError, SessionState, VoiceHost, VoiceOutputs};

/// How often a quiet brain's buffered words are held against the
/// cadence's longest wait.
pub(super) const CHUNK_TICK: Duration = Duration::from_millis(50);

/// One thing the owner's brain hands back, in the order it made them.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceBrainOut {
    /// The generation of the request the brain was started with.
    pub generation: GenerationEpoch,
    pub event: BrainEvent,
    /// A trusted host mark: the event carries external context, such as a
    /// tool result. It only adds to the generation's taint.
    pub externally_tainted: bool,
}

/// What the host hands the owner's playout, in order.
pub enum VoicePlayout {
    /// Spoken audio. Check it again when it is dequeued.
    Pcm(PlayoutFrame),
    /// The generation's last audio is above. Once all of it has played on
    /// the server and the client, answer
    /// [`VoiceMediaIn::Drained`](super::VoiceMediaIn::Drained) with it.
    End(GenerationEpoch),
}

/// Spoken audio for the owner's playout, gated by the session that made it.
pub struct PlayoutFrame {
    frame: PcmFrame,
    session: Weak<Mutex<SessionState>>,
}

impl PlayoutFrame {
    #[must_use]
    pub fn generation(&self) -> GenerationEpoch {
        self.frame.generation
    }

    /// Whether the frame's generation still plays. A stop, a newer
    /// generation or the session's end closes it, as they close the
    /// session's `accepts_pcm`. Check at each dequeue or device packet.
    #[must_use]
    pub fn is_current(&self) -> bool {
        let Some(session) = self.session.upgrade() else {
            return false;
        };
        let Ok(state) = session.lock() else {
            return false;
        };
        state.core.accepts_pcm(self.frame.generation)
    }

    /// The frame, while its generation still plays. Call right before it
    /// plays.
    #[must_use]
    pub fn current(self) -> Option<PcmFrame> {
        self.is_current().then_some(self.frame)
    }
}

/// The generation the host speaks, while its audio is open.
pub(super) struct Speech {
    generation: GenerationEpoch,
    chunker: VoiceChunker,
    /// Sentences the TTS seam took, each one call.
    sent: u64,
    /// Sentences whose audio came back.
    spoken: u64,
    /// The brain is done and the TTS seam was told no sentence follows.
    pub(super) ended: bool,
    /// Playout was told the generation's last audio is handed over.
    end_sent: bool,
    /// The owner's playout played it all.
    drained: bool,
}

/// A sentence's verdict, or why it has none.
pub(super) struct Verdict {
    generation: GenerationEpoch,
    outcome: oneiron::Result<SentenceEnforcement>,
}

/// Sentence safeguards still running, polled beside the connection; they
/// end with it.
pub(super) type Verdicts = FuturesUnordered<Pin<Box<dyn Future<Output = Verdict> + Send>>>;

/// Runs each sentence's safeguard on the owner plane, on the pass's own
/// backend and meter, beside the sentence's speech.
struct HostSafeguard<'a> {
    backend: &'a Arc<dyn LlmBackend>,
    budget: &'a BudgetGuard,
    verdicts: &'a mut Verdicts,
}

impl Safeguard for HostSafeguard<'_> {
    fn submit(&mut self, request: SafeguardRequest) -> oneiron::Result<()> {
        let backend = Arc::clone(self.backend);
        let budget = self.budget.clone();
        self.verdicts.push(Box::pin(async move {
            let generation = request.generation();
            let outcome = request
                .enforce_with_budget(&PolicyModelConfig::default(), backend.as_ref(), &budget)
                .await;
            Verdict {
                generation,
                outcome,
            }
        }));
        Ok(())
    }
}

/// A cadence the chunker takes, checked when the bindings are built.
pub(super) fn chunker(policy: &VoiceChunkPolicy) -> Option<VoiceChunker> {
    VoiceChunker::with_policy(policy.clone())
}

impl VoiceHost {
    /// Opens the generation's speech before its brain starts. A refusal,
    /// such as a banked voice whose consent no longer reaches the route,
    /// stops the generation; `false` then.
    pub(super) fn start_speech<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        generation: GenerationEpoch,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) -> bool {
        if let Err(error) = outputs.tts.submit(TtsCommand::Start { generation }) {
            tracing::warn!(%error, "voice media: speech did not start");
            self.output_failed(generation, bridge, outputs);
            return false;
        }
        bridge.speech = Some(Speech {
            generation,
            chunker: chunker(&bridge.chunking).unwrap_or_default(),
            sent: 0,
            spoken: 0,
            ended: false,
            end_sent: false,
            drained: false,
        });
        true
    }

    /// One of the brain's events, through the session first.
    pub(super) async fn brain_out<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        out: VoiceBrainOut,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) -> io::Result<()> {
        let VoiceBrainOut {
            generation,
            event,
            externally_tainted,
        } = out;
        if matches!(event, BrainEvent::Done) {
            // A trailing sentence is completed before the session hears Done.
            let tail =
                speech_mut(bridge, generation).and_then(|speech| speech.chunker.tick(u64::MAX));
            if !self.speak(generation, tail, bridge, outputs) {
                return Ok(());
            }
        }
        let accepted = self.lock().and_then(|mut state| {
            let event = state
                .core
                .handle_brain(generation, event, externally_tainted)?;
            let context = matches!(event, Some(BrainEvent::Tool(_)))
                .then(|| state.core.brain_context(generation).cloned())
                .flatten();
            Ok((event, context))
        });
        match accepted {
            Ok((Some(BrainEvent::TextDelta(text)), _)) => {
                let now = bridge.now_ms();
                let sentences = speech_mut(bridge, generation)
                    .map(|speech| {
                        let delta = LlmStreamEvent::TextDelta {
                            part_id: String::new(),
                            text,
                        };
                        speech.chunker.observe(&delta, now)
                    })
                    .unwrap_or_default();
                self.speak(generation, sentences, bridge, outputs);
            }
            // The model resumes on the tool context the session accepted.
            Ok((Some(BrainEvent::Tool(_)), Some(context))) => {
                if let Err(error) = outputs.brain.update_context(&context) {
                    tracing::warn!(%error, "voice media: the brain's context was not updated");
                    self.output_failed(generation, bridge, outputs);
                }
            }
            Ok((Some(BrainEvent::Done), _)) => self.brain_done(generation, bridge, outputs).await?,
            Ok((Some(BrainEvent::Error(_)), _)) => {
                tracing::warn!("voice media: the brain broke off");
                self.output_failed(generation, bridge, outputs);
            }
            // A stale generation's event, or text for closed audio.
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "voice media: a brain event was refused");
                self.output_failed(generation, bridge, outputs);
            }
        }
        Ok(())
    }

    /// The cadence's wait ran out on a quiet brain: its buffered words are
    /// a sentence.
    pub(super) fn speech_tick<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        let now = bridge.now_ms();
        let Some((generation, text)) = bridge
            .speech
            .as_mut()
            .filter(|speech| !speech.ended)
            .and_then(|speech| Some((speech.generation, speech.chunker.tick(now)?)))
        else {
            return;
        };
        self.speak(generation, Some(text), bridge, outputs);
    }

    /// One sentence's audio: handed over only for the session's current
    /// generation, and checked again when it is dequeued.
    pub(super) async fn spoken(&self, frame: PcmFrame, bridge: &mut MediaBridge) -> io::Result<()> {
        if let Some(speech) = speech_mut(bridge, frame.generation) {
            speech.spoken = speech.spoken.saturating_add(1);
        }
        if let Some(frame) = self.filter_pcm(frame) {
            let frame = PlayoutFrame {
                frame,
                session: Arc::downgrade(&self.state),
            };
            bridge.play(VoicePlayout::Pcm(frame)).await?;
        }
        self.end_playout(bridge).await
    }

    /// A sentence's verdict: its control and every notice are delivered,
    /// and a halt stops the audio. A safeguard that did not run stops the
    /// generation.
    pub(super) fn verdict<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        verdict: Verdict,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        let Verdict {
            generation,
            outcome,
        } = verdict;
        let enforcement = match outcome {
            Ok(enforcement) => enforcement,
            Err(error) => {
                tracing::warn!(%error, "voice media: a sentence's safeguard did not run");
                self.output_failed(generation, bridge, outputs);
                return;
            }
        };
        // Every notice is said, a stale sentence's too.
        let notices: Vec<_> = enforcement
            .enforcement()
            .system_notices
            .iter()
            .filter(|notice| notice.audience == "user_and_model")
            .cloned()
            .collect();
        let update = self
            .lock()
            .ok()
            .and_then(|mut state| state.core.apply_safeguard(enforcement));
        let mut undelivered = false;
        if let Some(update) = update {
            if let Some(stop) = &update.stop {
                stopped(stop, bridge, outputs);
            }
            undelivered |= outputs.control.submit(update.control).is_err();
        }
        for notice in notices {
            undelivered |= outputs
                .control
                .submit(ControlEvent::Notice { generation, notice })
                .is_err();
        }
        if undelivered {
            tracing::warn!("voice media: a safeguard's status was not delivered");
        }
        if speech_mut(bridge, generation).is_some_and(|speech| speech.drained) {
            self.finish(generation, bridge);
        }
    }

    /// The owner's playout played all of `generation`'s audio. An early or
    /// stale acknowledgement changes nothing.
    pub(super) fn drained(&self, generation: GenerationEpoch, bridge: &mut MediaBridge) {
        let Some(speech) = speech_mut(bridge, generation).filter(|speech| speech.end_sent) else {
            return;
        };
        speech.drained = true;
        self.finish(generation, bridge);
    }

    /// Stops `generation` when its output broke off.
    pub(super) fn output_failed<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        generation: GenerationEpoch,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        let stop = self
            .lock()
            .ok()
            .and_then(|mut state| state.core.fail_output(generation));
        if let Some(stop) = stop {
            stopped(&stop, bridge, outputs);
        }
    }

    /// Each sentence through the session, then to the TTS seam and its
    /// safeguard at once. `false` once the generation was stopped.
    fn speak<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        generation: GenerationEpoch,
        sentences: impl IntoIterator<Item = String>,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) -> bool {
        for text in sentences {
            let work = self
                .lock()
                .and_then(|mut state| Ok(state.core.complete_sentence(generation, text)?));
            match work {
                Ok(Some(work)) => {
                    let mut safeguard = HostSafeguard {
                        backend: self.backend(),
                        budget: self.budget(),
                        verdicts: &mut bridge.verdicts,
                    };
                    if work.dispatch(&mut outputs.tts, &mut safeguard).is_empty() {
                        if let Some(speech) = speech_mut(bridge, generation) {
                            speech.sent = speech.sent.saturating_add(1);
                        }
                        continue;
                    }
                    tracing::warn!("voice media: a sentence was not handed to speech");
                }
                // Its audio closed: what it would have said is dropped.
                Ok(None) => continue,
                Err(error) => tracing::warn!(%error, "voice media: a sentence was refused"),
            }
            self.output_failed(generation, bridge, outputs);
            return false;
        }
        true
    }

    /// The brain is done: no sentence follows. A generation whose audio a
    /// safeguard already closed waits on no playout.
    async fn brain_done<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        generation: GenerationEpoch,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) -> io::Result<()> {
        if speech_mut(bridge, generation).is_none() {
            self.finish(generation, bridge);
            return Ok(());
        }
        if let Err(error) = outputs.tts.submit(TtsCommand::End { generation }) {
            tracing::warn!(%error, "voice media: speech did not end");
            self.output_failed(generation, bridge, outputs);
            return Ok(());
        }
        if let Some(speech) = speech_mut(bridge, generation) {
            speech.ended = true;
        }
        self.end_playout(bridge).await
    }

    /// Marks the generation's last audio for playout, once the brain is
    /// done and every sentence's audio came back.
    async fn end_playout(&self, bridge: &mut MediaBridge) -> io::Result<()> {
        let Some(speech) = bridge
            .speech
            .as_mut()
            .filter(|speech| speech.ended && !speech.end_sent && speech.spoken >= speech.sent)
        else {
            return Ok(());
        };
        speech.end_sent = true;
        let generation = speech.generation;
        bridge.play(VoicePlayout::End(generation)).await
    }

    /// Closes `generation` once its brain, every verdict and its playout
    /// are done. A verdict still out finishes it when it lands.
    fn finish(&self, generation: GenerationEpoch, bridge: &mut MediaBridge) {
        let finished = self
            .lock()
            .and_then(|mut state| Ok::<_, HostError>(state.core.finish_playout(generation)?));
        if finished.is_ok() && speech_mut(bridge, generation).is_some() {
            bridge.speech = None;
        }
    }
}

fn speech_mut(bridge: &mut MediaBridge, generation: GenerationEpoch) -> Option<&mut Speech> {
    bridge
        .speech
        .as_mut()
        .filter(|speech| speech.generation == generation)
}

/// Submits a stop to every output arm and drops the stopped generation's
/// speech; a failed arm is logged.
pub(super) fn stopped<B: Brain, T: TtsSeamClient, C: CascadeControl>(
    stop: &OutputStop,
    bridge: &mut MediaBridge,
    outputs: &mut VoiceOutputs<B, T, C>,
) {
    if let Some(generation) = stop.generation
        && speech_mut(bridge, generation).is_some()
    {
        bridge.speech = None;
    }
    let errors = stop.dispatch(&mut outputs.brain, &mut outputs.tts, &mut outputs.control);
    if !errors.is_empty() {
        tracing::warn!(
            count = errors.len(),
            "voice media: a stop arm was not delivered"
        );
    }
}
