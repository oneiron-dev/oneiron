//! The host's own speech and hearing on the media seats (OF-410). The
//! owner's microphone audio is heard on the vault's live ASR route and the
//! brain's sentences are spoken on its live TTS route, both picked by
//! [`ModelRuntime::voice_route`] and sent through the runtime as the media
//! door (`Arc::clone(server.ai.models())`), so each call is admitted on its
//! own permit and settled on the media meter.
//!
//! A heard utterance enters the session as an ASR final: it is enriched
//! outside the session lock and applied through `handle_asr`, as a final
//! from the wire is. Spoken audio passes the session's `filter_pcm` before
//! it reaches the owner's playout, so a stopped or stale generation never
//! plays; a stop flushes what the owner still queues through its
//! `CascadeControl`. A banked voice renders only under its render consent
//! for the TTS route's target and locality: it is bound when the bindings
//! are built, again when each generation starts, and checked before each
//! sentence is sent and before its audio comes back.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::llm::VoiceLane;
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
    /// The owner's audio side: microphone audio, cuts and VAD.
    pub audio_in: mpsc::Receiver<VoiceMediaIn>,
    /// Spoken audio for playout, past the session's filter.
    pub playout: mpsc::Sender<PcmFrame>,
    /// How many calls the media queue holds.
    pub queue_capacity: usize,
}

impl VoiceMediaBindings {
    /// The vault's live ASR and TTS routes on the door, one media queue and
    /// its worker, and the TTS seam. A lane with no live voice row, or a
    /// banked voice whose render consent does not reach the TTS route,
    /// refuses.
    pub(super) fn build(self) -> oneiron::Result<(MediaTts, MediaBridge, MediaWorker)> {
        let asr_route = self.door.voice_route(&self.vault, VoiceLane::AsrLive, None)?;
        let tts_route = self.door.voice_route(&self.vault, VoiceLane::TtsLive, None)?;
        let (queue, worker) = voice_media_channel(self.queue_capacity);
        let tts = MediaTts::new(Arc::clone(&self.vault), tts_route, self.render, queue.clone())?;
        let asr = MediaAsrAdapter::new(asr_route, self.sample_rate, self.channels, queue)?;
        let (deliver, outputs) = mpsc::unbounded_channel();
        Ok((
            tts,
            MediaBridge {
                asr,
                audio_in: Some(self.audio_in),
                outputs,
                playout: self.playout,
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
/// shared media queue. Clones share it: the brain's stream driver
/// (`drive_voice_stream`) submits its sentences through one, and the served
/// connection's stops go through another.
#[derive(Clone)]
pub struct MediaTts(Arc<Mutex<MediaTtsState>>);

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
    outputs: mpsc::UnboundedReceiver<VoiceMediaOutput>,
    playout: mpsc::Sender<PcmFrame>,
    /// The session's VAD clock starts here.
    started: Instant,
    next_utterance: u64,
}

/// One thing the bridge has for the served connection.
pub(super) enum MediaEvent {
    In(VoiceMediaIn),
    Out(VoiceMediaOutput),
    /// The worker stopped: nothing more is heard or spoken.
    Stopped,
}

impl MediaBridge {
    /// The owner's next input, or the worker's next output.
    pub(super) async fn next(&mut self) -> MediaEvent {
        loop {
            let Some(audio_in) = self.audio_in.as_mut() else {
                return self
                    .outputs
                    .recv()
                    .await
                    .map_or(MediaEvent::Stopped, MediaEvent::Out);
            };
            tokio::select! {
                input = audio_in.recv() => match input {
                    Some(input) => return MediaEvent::In(input),
                    None => self.audio_in = None,
                },
                output = self.outputs.recv() => {
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

    /// Hands spoken audio to the owner's playout.
    pub(super) async fn play(&self, frame: PcmFrame) -> io::Result<()> {
        self.playout
            .send(frame)
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
            VoiceMediaIn::Speaking(speaking) => self
                .observe_speech(bridge.now(), speaking)
                .map(|stop| {
                    if let Some(stop) = stop {
                        dispatch(&stop, outputs);
                    }
                }),
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

    /// A sentence that could not be spoken stops the generation's audio:
    /// its queued speech and the PCM the owner still holds.
    pub(super) fn speech_failed<B, T: TtsSeamClient, C: CascadeControl>(
        generation: GenerationEpoch,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        tracing::warn!("voice media: a sentence was not spoken");
        let flushed = outputs.control.flush_queued_pcm(generation);
        let cancelled = outputs.tts.submit(TtsCommand::Cancel { generation });
        if flushed.is_err() || cancelled.is_err() {
            tracing::warn!("voice media: a failed sentence's stop was not delivered");
        }
    }

    fn observe_speech(&self, now: Duration, speaking: bool) -> Result<Option<OutputStop>, HostError> {
        Ok(self.lock()?.core.observe_speech(now, speaking)?)
    }
}

/// Submits a stop to every output arm; a failed arm is logged.
fn dispatch<B: Brain, T: TtsSeamClient, C: CascadeControl>(
    stop: &OutputStop,
    outputs: &mut VoiceOutputs<B, T, C>,
) {
    let errors = stop.dispatch(&mut outputs.brain, &mut outputs.tts, &mut outputs.control);
    if !errors.is_empty() {
        tracing::warn!(count = errors.len(), "voice media: a stop arm was not delivered");
    }
}
