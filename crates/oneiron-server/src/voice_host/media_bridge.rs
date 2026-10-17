//! The host's own speech and hearing on the media seats (OF-410). The
//! owner's microphone audio is heard on the vault's live ASR route and the
//! brain's sentences are spoken on its live TTS route, both picked by
//! [`ModelRuntime::voice_route`] and sent through the runtime as the media
//! door (`Arc::clone(server.ai.models())`), so each call is admitted on its
//! own permit and settled on the media meter.
//!
//! A heard utterance enters the session as an ASR final: it is enriched
//! outside the session lock and applied through `handle_asr`, as a final
//! from the wire is. The brain's reply comes back through the session's
//! sentence safeguards before it is spoken (`speech`). Spoken audio passes
//! the session's `filter_pcm` before it reaches the owner's playout, and
//! again when playout dequeues it, so a stopped or stale generation never
//! plays; a stop flushes what the owner still queues through its
//! `CascadeControl`. A banked voice renders only under its render consent
//! for the TTS route's target and locality: it is bound when the bindings
//! are built, again when each generation starts, and checked before each
//! sentence is sent and before its audio comes back. A roster change the
//! owner reports stops a generation assembled for the old audience before
//! the next audio plays.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::llm::{VoiceChunkPolicy, VoiceLane};
use oneiron::voice_cascade::media::{
    BankVoiceBinding, MediaAsrAdapter, MediaTtsAdapter, MediaVoiceRoute, VoiceMediaOutput,
    VoiceMediaQueue, VoiceMediaSender, VoiceMediaWork, VoiceMediaWorker, VoiceRender,
    voice_media_channel,
};
use oneiron::voice_cascade::{
    AsrEvent, AsrEventKind, AsrStream, Brain, CascadeControl, GenerationEpoch, OutputStop,
    PcmFrame, TtsCommand, TtsSeamClient,
};
use tokio::sync::mpsc;

use super::speech::{self, CHUNK_TICK, Speech, Verdict, Verdicts, VoiceBrainOut, VoicePlayout};
use super::{EnrichmentWork, HostError, VoiceHost, VoiceOutputs};
use crate::models::ModelRuntime;

/// The revision a heard utterance's final carries: each cut is an
/// utterance of its own, heard once.
pub(super) const HEARD_REVISION: u64 = 1;

fn invalid(message: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("voice host media: {message}"))
}

/// What the owner's audio side hands the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceMediaIn {
    /// Microphone audio: PCM16LE at the bindings' rate and channels.
    Pcm(Vec<u8>),
    /// The owner's VAD or turn detector ends an utterance here: what was
    /// heard since the last cut is transcribed as one call.
    Cut,
    /// A VAD observation: whether the person has been speaking since the
    /// last one. Sustained speech over the assistant's output stops it.
    Speaking(bool),
    /// The voice roster changed: someone joined, a speaker was placed
    /// differently, or the owner named one. The session reads its audience
    /// again, and a changed one stops the live generation before the next
    /// audio plays.
    RosterChanged,
    /// The owner's playout played all of a generation's audio, up to its
    /// [`VoicePlayout::End`], on the server and the client. The generation
    /// finishes once its brain and every sentence's verdict are done too.
    Drained(GenerationEpoch),
}

/// The media side of one served voice connection.
pub struct VoiceMediaBindings {
    /// The media door: `Arc::clone(server.ai.models())`.
    pub door: Arc<ModelRuntime>,
    /// The vault the host serves; its live voice rows pick both routes.
    pub vault: Arc<Vault>,
    /// The voice the assistant speaks in.
    pub render: VoiceRender,
    /// The rate and channels of the microphone's PCM16LE.
    pub sample_rate: u32,
    pub channels: u16,
    /// The owner's audio side: microphone audio, cuts, VAD and drains.
    pub audio_in: mpsc::Receiver<VoiceMediaIn>,
    /// The brain's events, sent by the brain the connection starts.
    pub brain_out: mpsc::Receiver<VoiceBrainOut>,
    /// The session's cadence for cutting the brain's text into sentences.
    pub chunking: VoiceChunkPolicy,
    /// Spoken audio for playout, past the session's filter, and each
    /// generation's end.
    pub playout: mpsc::Sender<VoicePlayout>,
    /// How many calls the media queue holds.
    pub queue_capacity: usize,
}

impl VoiceMediaBindings {
    /// The vault's live ASR and TTS routes on the door, one media queue and
    /// its worker, and the TTS seam. A lane with no live voice row, a
    /// banked voice whose render consent does not reach the TTS route, or a
    /// cadence that could never cut a sentence, refuses.
    pub(super) fn build(self) -> oneiron::Result<(MediaTts, MediaBridge, MediaWorker)> {
        if speech::chunker(&self.chunking).is_none() {
            return Err(invalid("voice chunk policy"));
        }
        let asr_route = self
            .door
            .voice_route(&self.vault, VoiceLane::AsrLive, None)?;
        let tts_route = self
            .door
            .voice_route(&self.vault, VoiceLane::TtsLive, None)?;
        let (queue, worker) = voice_media_channel(self.queue_capacity);
        let tts = MediaTts::new(
            Arc::clone(&self.vault),
            tts_route,
            self.render,
            queue.clone(),
        )?;
        let asr = MediaAsrAdapter::new(asr_route, self.sample_rate, self.channels, queue.clone())?;
        let (deliver, outputs) = mpsc::unbounded_channel();
        Ok((
            tts,
            MediaBridge {
                asr,
                audio_in: Some(self.audio_in),
                brain_out: Some(self.brain_out),
                outputs,
                playout: self.playout,
                chunking: self.chunking,
                queue,
                speech: None,
                verdicts: Verdicts::new(),
                tick_at: None,
                started: Instant::now(),
                next_utterance: 0,
            },
            MediaWorker {
                worker,
                door: self.door,
                vault: self.vault,
                deliver,
            },
        ))
    }
}

/// The bridge's TTS seam: one [`MediaTtsAdapter`] per generation over the
/// shared media queue. Only the served connection speaks through it: the
/// brain's sentences pass the session's safeguards first.
pub(super) struct MediaTts(Arc<Mutex<MediaTtsState>>);

struct MediaTtsState {
    vault: Arc<Vault>,
    route: MediaVoiceRoute,
    render: VoiceRender,
    queue: VoiceMediaSender,
    current: Option<(GenerationEpoch, MediaTtsAdapter<VoiceMediaSender>)>,
}

impl MediaTts {
    fn new(
        vault: Arc<Vault>,
        route: MediaVoiceRoute,
        render: VoiceRender,
        queue: VoiceMediaSender,
    ) -> oneiron::Result<Self> {
        // A banked voice binds before any generation: no render consent
        // reaching the route's target and locality, no bindings.
        match &render {
            VoiceRender::Stock(_) => {}
            VoiceRender::Bank {
                voice_id, register, ..
            } if route.reference_target => {
                BankVoiceBinding::bind_reference(
                    &vault,
                    voice_id,
                    &route.target,
                    register.as_deref(),
                    route.locality,
                )?;
            }
            VoiceRender::Bank {
                voice_id,
                include_generated,
                ..
            } => {
                BankVoiceBinding::bind(
                    &vault,
                    voice_id,
                    &route.target,
                    *include_generated,
                    route.locality,
                )?;
            }
        }
        Ok(Self(Arc::new(Mutex::new(MediaTtsState {
            vault,
            route,
            render,
            queue,
            current: None,
        }))))
    }
}

impl TtsSeamClient for MediaTts {
    fn submit(&mut self, command: TtsCommand) -> oneiron::Result<()> {
        let mut guard = self.0.lock().map_err(|_| invalid("TTS seam poisoned"))?;
        let state = &mut *guard;
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if matches!(command, TtsCommand::Start { .. }) {
            // Each generation speaks through an adapter of its own, which
            // binds the banked voice again before any word.
            let mut adapter = MediaTtsAdapter::new(
                Arc::clone(&state.vault),
                state.route.clone(),
                state.render.clone(),
                state.queue.clone(),
            )?;
            adapter.submit(command)?;
            state.current = Some((generation, adapter));
            return Ok(());
        }
        match &mut state.current {
            Some((current, adapter)) if *current == generation => adapter.submit(command),
            // A stop for a generation this seam never started still drops
            // whatever it queued.
            _ if matches!(command, TtsCommand::Cancel { .. }) => state
                .queue
                .try_submit(VoiceMediaWork::Cancel { generation }),
            _ => Err(invalid("unmatched generation")),
        }
    }
}

/// The served connection's side of the bridge: what it hears, and what the
/// worker hands back.
pub(super) struct MediaBridge {
    asr: MediaAsrAdapter<VoiceMediaSender>,
    /// `None` once the owner's audio side closed.
    audio_in: Option<mpsc::Receiver<VoiceMediaIn>>,
    /// `None` once the brain's side closed.
    brain_out: Option<mpsc::Receiver<VoiceBrainOut>>,
    outputs: mpsc::UnboundedReceiver<VoiceMediaOutput>,
    playout: mpsc::Sender<VoicePlayout>,
    pub(super) chunking: VoiceChunkPolicy,
    /// The media queue, read for room before a sentence is sent.
    pub(super) queue: VoiceMediaSender,
    /// The generation being spoken, while its audio is open.
    pub(super) speech: Option<Speech>,
    pub(super) verdicts: Verdicts,
    /// When a quiet brain's buffered words are next held against the
    /// cadence; kept across polls, so steady microphone audio cannot
    /// starve it.
    tick_at: Option<tokio::time::Instant>,
    /// The session's VAD and cadence clock starts here.
    started: Instant,
    next_utterance: u64,
}

/// One thing the bridge has for the served connection.
pub(super) enum MediaEvent {
    In(VoiceMediaIn),
    Out(VoiceMediaOutput),
    Brain(VoiceBrainOut),
    Verdict(Verdict),
    /// The cadence's clock: buffered words may be due as a sentence.
    Tick,
    /// The worker stopped: nothing more is heard or spoken.
    Stopped,
}

impl MediaBridge {
    /// The owner's next input, the brain's next event, a verdict, the
    /// cadence's clock, or the worker's next output.
    pub(super) async fn next(&mut self) -> MediaEvent {
        loop {
            let Self {
                audio_in,
                brain_out,
                outputs,
                speech,
                verdicts,
                tick_at,
                ..
            } = &mut *self;
            let ticking = speech.as_ref().is_some_and(|speech| !speech.ended);
            let tick = if ticking {
                *tick_at.get_or_insert_with(|| tokio::time::Instant::now() + CHUNK_TICK)
            } else {
                *tick_at = None;
                tokio::time::Instant::now()
            };
            tokio::select! {
                input = recv(audio_in) => match input {
                    Some(input) => return MediaEvent::In(input),
                    None => *audio_in = None,
                },
                out = recv(brain_out) => match out {
                    Some(out) => return MediaEvent::Brain(out),
                    None => *brain_out = None,
                },
                Some(verdict) = futures_util::StreamExt::next(verdicts), if !verdicts.is_empty() => {
                    return MediaEvent::Verdict(verdict);
                }
                () = tokio::time::sleep_until(tick), if ticking => {
                    *tick_at = None;
                    return MediaEvent::Tick;
                }
                output = outputs.recv() => {
                    return output.map_or(MediaEvent::Stopped, MediaEvent::Out);
                }
            }
        }
    }

    /// Hears the owner's audio. An utterance at one call's limit is cut,
    /// and the audio starts the next.
    fn hear(&mut self, pcm: &[u8]) -> oneiron::Result<()> {
        if self.asr.accept_audio(pcm).is_err() {
            self.asr.cut()?;
            self.asr.accept_audio(pcm)?;
        }
        Ok(())
    }

    /// Hands spoken audio, or a generation's end, to the owner's playout.
    pub(super) async fn play(&mut self, playout: VoicePlayout) -> io::Result<()> {
        self.playout
            .send(playout)
            .await
            .map_err(|_| io::Error::other("voice playout closed"))
    }

    fn utterance_id(&mut self) -> String {
        self.next_utterance = self.next_utterance.saturating_add(1);
        format!("heard-{}", self.next_utterance)
    }

    fn now(&self) -> Duration {
        self.started.elapsed()
    }

    pub(super) fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// The receiver's next item; forever once it is gone.
async fn recv<T>(receiver: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// The worker that runs the bridge's media calls through the door, outside
/// the session lock.
pub(super) struct MediaWorker {
    worker: VoiceMediaWorker,
    door: Arc<ModelRuntime>,
    vault: Arc<Vault>,
    deliver: mpsc::UnboundedSender<VoiceMediaOutput>,
}

impl MediaWorker {
    /// Runs until every queue sender is gone. Dropping it drops the call in
    /// flight, whose permit settles as it would for any dropped call.
    pub(super) async fn run(self) {
        let Self {
            worker,
            door,
            vault,
            deliver,
        } = self;
        worker
            .run(door.as_ref(), &vault, move |output| {
                deliver.send(output).ok();
            })
            .await;
    }
}

impl VoiceHost {
    /// The session's current generation's audio; `None` for a stopped or
    /// stale one.
    pub(super) fn filter_pcm(&self, frame: PcmFrame) -> Option<PcmFrame> {
        self.lock().ok()?.core.filter_pcm(frame)
    }

    /// One input from the owner's audio side. A refusal is logged, never
    /// reflected to the wire.
    pub(super) fn media_in<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        input: VoiceMediaIn,
        bridge: &mut MediaBridge,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        let handled = match input {
            VoiceMediaIn::Pcm(pcm) => bridge.hear(&pcm).map_err(HostError::from),
            VoiceMediaIn::Cut => bridge.asr.cut().map(drop).map_err(HostError::from),
            VoiceMediaIn::Speaking(speaking) => {
                self.observe_speech(bridge.now(), speaking).map(|stop| {
                    if let Some(stop) = stop {
                        speech::stopped(&stop, bridge, outputs);
                    }
                })
            }
            VoiceMediaIn::RosterChanged => self.refresh_interlocutors().map(|stop| {
                if let Some(stop) = stop {
                    speech::stopped(&stop, bridge, outputs);
                }
            }),
            VoiceMediaIn::Drained(generation) => {
                self.drained(generation, bridge);
                Ok(())
            }
        };
        if let Err(error) = handled {
            tracing::warn!(%error, "voice media input refused");
        }
    }

    /// A heard utterance as the session's next final: opened, then prepared
    /// for enrichment outside the lock. An endpoint heard nothing; an error
    /// is logged.
    pub(super) fn heard(
        &self,
        bridge: &mut MediaBridge,
        event: AsrEvent,
    ) -> Option<(String, EnrichmentWork<'_>)> {
        match event.kind {
            AsrEventKind::Final if !event.text.trim().is_empty() => {}
            AsrEventKind::Error => {
                tracing::warn!("voice media: an utterance was not heard");
                return None;
            }
            _ => return None,
        }
        let handle = match self.open(bridge.utterance_id()) {
            Ok(handle) => handle,
            Err(error) => {
                tracing::warn!(%error, "voice media: heard utterance not opened");
                return None;
            }
        };
        match self.prepare(&handle, HEARD_REVISION, event.text, true) {
            Ok(work) => Some((handle, work)),
            Err(error) => {
                tracing::warn!(%error, "voice media: heard utterance refused");
                self.close(&handle).ok();
                None
            }
        }
    }

    fn observe_speech(
        &self,
        now: Duration,
        speaking: bool,
    ) -> Result<Option<OutputStop>, HostError> {
        Ok(self.lock()?.core.observe_speech(now, speaking)?)
    }

    /// The roster-change stop: the generation assembled for an audience
    /// that changed.
    fn refresh_interlocutors(&self) -> Result<Option<OutputStop>, HostError> {
        Ok(self.lock()?.core.refresh_interlocutors()?.stop)
    }
}
