//! The cascade's speech and hearing on the host's media seats (OF-410).
//! [`MediaTtsAdapter`] and [`MediaAsrAdapter`] are the cascade's TTS and ASR
//! ports over `ai.speech` and `ai.transcribe`. Each SUBMITS bounded work to
//! a [`VoiceMediaQueue`] and never waits. The host's [`VoiceMediaWorker`]
//! runs that work outside the session lock through its [`AiMediaDoor`], so
//! every call is admitted on its own permit, sent through its run's media
//! gate and settled in its native units (characters spoken, seconds heard),
//! as every other media call is.
//!
//! A route ([`MediaVoiceRoute`]) is one media rung. The host picks it before
//! any work from the vault's voice row for the lane
//! (`Vault::select_voice_backend`), and the vault's inference policy admits
//! it; a call never falls back to another target. A banked voice
//! ([`VoiceRender::Bank`]) renders only on its recorded clone for the
//! route's target (ARCH-0061 §5: identity lives in the bank, vendors are
//! render targets), or, on a target that keeps no clone (the own-server
//! VoxCPM2 worker), from the identity's source clip fenced at the bank's
//! revision of its refs. An unprovisioned, evicted, stale or withdrawn
//! voice refuses the generation rather than speak in another voice. The
//! bank is read again before each call is queued, before it is sent, and
//! before its audio is handed back.
//!
//! These calls are buffered: one call per flushed sentence and one per cut
//! utterance. Live partial transcripts (Soniox) ride a [`LeasedAsrStream`]
//! instead: one permit per bounded stream, opened through the host's
//! [`VoiceStreamDoor`], with each chunk of audio metered on its lease before
//! it leaves and the audio settled when the stream ends or is cancelled.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use tokio::sync::mpsc;

use super::{
    AsrEvent, AsrEventKind, AsrStream, GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::llm::media::wav::{WavClip, pcm16_wav};
use crate::llm::media::{
    AiMediaDoor, AiOperation, MediaFuture, MediaPart, MediaRequest, MediaResponse, MediaVoice,
};
use crate::llm::run_admission::MediaStreamLease;
use crate::llm::{CallEnvelope, LlmResult, ModelId, ModelLocality, ModelTierRef, VoiceLane};
use crate::voice_identity::ref_bank::{VoiceRefFence, VoiceRegisterClip, VoiceRenderGrant};

/// The most text one spoken call carries: a flushed sentence, with room.
pub const MAX_SENTENCE_BYTES: usize = 8 * 1024;
/// The longest utterance one transcription call carries; the host cuts
/// sooner.
pub const MAX_UTTERANCE_SECONDS: u32 = 120;
/// The most audio one live stream holds its permit for. A longer live
/// session ends its stream and opens the next on a fresh permit.
pub const MAX_STREAM_AUDIO_MS: u64 = 10 * 60 * 1_000;

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("voice media: {message}"))
}

/// One media rung a voice lane runs on, as the host's routing picked it.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaVoiceRoute {
    pub lane: VoiceLane,
    /// The rung's own id: each call takes this rung alone.
    pub model: ModelId,
    /// The voice tier the vault's row named, which the rung is bound to.
    pub tier: ModelTierRef,
    pub locality: ModelLocality,
    /// The render target the reference bank keys this rung's clones by.
    pub target: String,
    /// Whether the target renders from the identity's reference clip on
    /// each call and keeps no clone (the own-server VoxCPM2 worker).
    pub reference_target: bool,
    /// The vault's admission of the route; every call carries it.
    pub envelope: CallEnvelope,
}

impl MediaVoiceRoute {
    /// The media call the lane makes.
    #[must_use]
    pub fn operation(&self) -> AiOperation {
        match self.lane {
            VoiceLane::AsrLive | VoiceLane::AsrBatch => AiOperation::Transcribe,
            VoiceLane::TtsLive | VoiceLane::TtsBatch => AiOperation::Speech,
        }
    }

    fn request(&self, part: MediaPart, voice: Option<MediaVoice>) -> MediaRequest {
        let operation = self.operation();
        let mut params = BTreeMap::new();
        if operation == AiOperation::Speech {
            // WAV says its own rate and channels; the cascade plays PCM16.
            params.insert("response_format".to_owned(), "wav".into());
        }
        MediaRequest {
            model: self.model.clone(),
            envelope: self.envelope.clone(),
            operation,
            parts: vec![part],
            references: Vec::new(),
            params,
            voice,
        }
    }
}

/// The voice a speech route renders in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceRender {
    /// The provider's own voice, by its name: no banked identity.
    Stock(String),
    /// A banked identity, rendered as its recorded clone on the route's
    /// target, or from its source clip on a reference target. Generated
    /// refs join the source refs of a clone only when asked; a reference
    /// target renders `register`'s source clip (the identity's first when
    /// none is named) and never a generated one.
    Bank {
        voice_id: String,
        include_generated: bool,
        register: Option<String>,
    },
}

/// A banked identity bound for one render target, at the bank's revision
/// of it and under the voice's render consent. A withdrawn and re-recorded
/// clone, refs that changed, or a new render decision are a new revision,
/// so they never revive an older binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankVoiceBinding {
    pub voice_id: String,
    pub target: String,
    pub include_generated: bool,
    pub bound: BankBound,
}

/// What a binding holds for its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankBound {
    /// The target's recorded clone: its id for it, at that record's
    /// revision, under the render consent that reaches the target.
    Clone {
        vendor_voice_id: String,
        revision: [u8; 16],
        grant: VoiceRenderGrant,
    },
    /// The identity's source clip for a target that renders from it on
    /// each call, fenced at the identity's incarnation and refs.
    Reference {
        clip: VoiceRegisterClip,
        fence: VoiceRefFence,
    },
}

impl BankVoiceBinding {
    /// Binds `voice_id`'s current clone on `target`, a target at
    /// `locality`. An unprovisioned, evicted, stale or withdrawn clone
    /// refuses, as does a voice whose render consent does not reach it.
    pub fn bind(
        vault: &Vault,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<Self> {
        let (record, grant) = vault
            .voice_target_clone(voice_id, target, include_generated, locality)?
            .ok_or_else(|| invalid("voice target not provisioned, evicted or stale"))?;
        Ok(Self {
            voice_id: record.voice_id,
            target: record.target,
            include_generated,
            bound: BankBound::Clone {
                vendor_voice_id: record.vendor_voice_id,
                revision: record.revision,
                grant,
            },
        })
    }

    /// Binds `voice_id`'s source clip for a reference target: `register`'s,
    /// or the identity's first. The clip is the person's raw voice, so a
    /// third-party route refuses, as does an identity with no source refs
    /// or no render consent reaching `locality`, a clip that is not a WAV
    /// with its transcript, or one larger than the vault's serving policy
    /// allows.
    pub fn bind_reference(
        vault: &Vault,
        voice_id: &str,
        target: &str,
        register: Option<&str>,
        locality: ModelLocality,
    ) -> Result<Self> {
        if locality == ModelLocality::ThirdParty {
            return Err(invalid("a voice reference never goes to a third party"));
        }
        let limits = vault.voice_serving_limits(None)?;
        let (clip, fence) = vault.fenced_voice_reference(voice_id, target, register, locality)?;
        if clip.media_type != "audio/wav"
            || clip.audio.len() < 12
            || !clip.audio.starts_with(b"RIFF")
            || &clip.audio[8..12] != b"WAVE"
            || clip.transcript.trim().is_empty()
            || clip.audio.len() as u64 > limits.max_ref_bytes
        {
            return Err(invalid("a voice reference is a WAV with its transcript"));
        }
        Ok(Self {
            voice_id: voice_id.to_owned(),
            target: target.to_owned(),
            include_generated: false,
            bound: BankBound::Reference { clip, fence },
        })
    }

    /// Whether what this binding names is still the bank's current one,
    /// under the same render consent. A bank that cannot be read, or a
    /// withdrawal waiting to commit, is not current.
    #[must_use]
    pub fn is_current(&self, vault: &Vault) -> bool {
        match &self.bound {
            BankBound::Clone {
                revision, grant, ..
            } => matches!(
                vault.voice_target_clone(
                    &self.voice_id,
                    &self.target,
                    self.include_generated,
                    grant.locality,
                ),
                Ok(Some((record, current))) if record.revision == *revision && current == *grant
            ),
            BankBound::Reference { fence, .. } => vault
                .voice_ref_fence_current_now(&self.voice_id, &self.target, fence)
                .unwrap_or(false),
        }
    }

    /// The voice the call's wire carries: the target's id for the clone,
    /// or the fenced clip itself.
    #[must_use]
    pub fn voice(&self) -> MediaVoice {
        match &self.bound {
            BankBound::Clone {
                vendor_voice_id, ..
            } => MediaVoice::Clone {
                id: vendor_voice_id.clone(),
            },
            BankBound::Reference { clip, fence } => MediaVoice::Reference {
                voice_id: self.voice_id.clone(),
                owner: fence.owner.to_hex(),
                register: clip.register.clone(),
                revision: fence
                    .incarnation
                    .iter()
                    .flatten()
                    .chain(&fence.ref_digest)
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                media_type: clip.media_type.clone(),
                audio: clip.audio.clone(),
                transcript: clip.transcript.clone(),
            },
        }
    }
}

/// One item of voice media work, as an adapter queues it.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceMediaWork {
    /// One flushed sentence to speak, as one `ai.speech` call.
    Speech {
        generation: GenerationEpoch,
        submission: u64,
        request: MediaRequest,
        /// The banked voice it renders in, checked again before the call
        /// and before its audio is handed back.
        voice: Option<BankVoiceBinding>,
    },
    /// One cut utterance to hear, as one `ai.transcribe` call.
    Transcribe {
        submission: u64,
        request: MediaRequest,
    },
    /// Drops the generation's queued speech and its call in flight.
    Cancel { generation: GenerationEpoch },
}

/// FIFO, nonblocking admission: one work item or nothing. An error admits
/// nothing, and no call runs inside `try_submit`.
pub trait VoiceMediaQueue {
    fn try_submit(&mut self, work: VoiceMediaWork) -> Result<()>;
}

/// What the worker hands back to the host.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceMediaOutput {
    /// One spoken sentence's audio. Pass it through the session's
    /// `filter_pcm` at enqueue AND at playback; a stale epoch is dropped.
    Pcm { submission: u64, frame: PcmFrame },
    /// A sentence that was not spoken: stop the generation's output.
    SpeechFailed {
        generation: GenerationEpoch,
        submission: u64,
        error: String,
    },
    /// What one cut utterance said, as the ASR event the host feeds the
    /// session under its utterance handle: a final, an endpoint when it
    /// heard nothing, or an error.
    Heard { submission: u64, event: AsrEvent },
}

/// A bounded channel from adapters to one worker. Clone the sender for each
/// generation's adapter; the worker serves them all in order.
#[must_use]
pub fn voice_media_channel(capacity: usize) -> (VoiceMediaSender, VoiceMediaWorker) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    (
        VoiceMediaSender(sender),
        VoiceMediaWorker {
            work: receiver,
            pending: VecDeque::new(),
            cancelled: BTreeSet::new(),
        },
    )
}

#[derive(Clone)]
pub struct VoiceMediaSender(mpsc::Sender<VoiceMediaWork>);

impl VoiceMediaQueue for VoiceMediaSender {
    fn try_submit(&mut self, work: VoiceMediaWork) -> Result<()> {
        self.0.try_send(work).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => invalid("media queue full"),
            mpsc::error::TrySendError::Closed(_) => invalid("media worker stopped"),
        })
    }
}

/// Runs queued voice media work, in order, through the host's door.
pub struct VoiceMediaWorker {
    work: mpsc::Receiver<VoiceMediaWork>,
    pending: VecDeque<VoiceMediaWork>,
    cancelled: BTreeSet<GenerationEpoch>,
}

impl VoiceMediaWorker {
    /// Runs every queued call until all senders are dropped. A cancel drops
    /// its generation's queued speech and the call in flight (which still
    /// pays for what it sent). A banked voice withdrawn before a call goes,
    /// or before its audio comes back, is not spoken.
    pub async fn run(
        mut self,
        door: &dyn AiMediaDoor,
        vault: &Vault,
        mut deliver: impl FnMut(VoiceMediaOutput),
    ) {
        loop {
            self.drain();
            let work = match self.pending.pop_front() {
                Some(work) => work,
                None => match self.work.recv().await {
                    Some(work) => {
                        self.take(work);
                        continue;
                    }
                    None => return,
                },
            };
            match work {
                VoiceMediaWork::Cancel { .. } => {}
                VoiceMediaWork::Speech {
                    generation,
                    submission,
                    request,
                    voice,
                } => {
                    let failed = |error: String| VoiceMediaOutput::SpeechFailed {
                        generation,
                        submission,
                        error,
                    };
                    if voice.as_ref().is_some_and(|voice| !voice.is_current(vault)) {
                        deliver(failed("voice withdrawn, evicted or stale".into()));
                        continue;
                    }
                    let Some(answer) = self.call(door.call(request), Some(generation)).await else {
                        continue;
                    };
                    let spoken = answer
                        .map_err(|error| error.to_string())
                        .and_then(|response| {
                            if voice.as_ref().is_some_and(|voice| !voice.is_current(vault)) {
                                return Err("voice withdrawn, evicted or stale".into());
                            }
                            spoken_frame(generation, &response).map_err(|error| error.to_string())
                        });
                    deliver(match spoken {
                        Ok(frame) => VoiceMediaOutput::Pcm { submission, frame },
                        Err(error) => failed(error),
                    });
                }
                VoiceMediaWork::Transcribe {
                    submission,
                    request,
                } => {
                    let started = Instant::now();
                    let Some(answer) = self.call(door.call(request), None).await else {
                        continue;
                    };
                    let latency = started.elapsed().as_secs_f64() * 1_000.0;
                    let event = match answer {
                        Ok(response) => heard(&response, latency),
                        Err(error) => asr_error(error.to_string()),
                    };
                    deliver(VoiceMediaOutput::Heard { submission, event });
                }
            }
        }
    }

    /// Takes what is already queued, without waiting.
    fn drain(&mut self) {
        while let Ok(work) = self.work.try_recv() {
            self.take(work);
        }
    }

    /// A cancel drops the generation's queued speech at once; anything else
    /// waits its turn.
    fn take(&mut self, work: VoiceMediaWork) {
        if let VoiceMediaWork::Cancel { generation } = work {
            self.cancelled.insert(generation);
            self.pending.retain(|queued| {
                !matches!(queued, VoiceMediaWork::Speech { generation: of, .. } if *of == generation)
            });
            return;
        }
        if let VoiceMediaWork::Speech { generation, .. } = &work
            && self.cancelled.contains(generation)
        {
            return;
        }
        self.pending.push_back(work);
    }

    /// Runs one call while taking what arrives meanwhile; `None` when
    /// `generation` was cancelled before it answered.
    async fn call<T>(
        &mut self,
        mut call: MediaFuture<'_, T>,
        generation: Option<GenerationEpoch>,
    ) -> Option<LlmResult<T>> {
        let mut open = true;
        std::future::poll_fn(|cx| {
            while open {
                match self.work.poll_recv(cx) {
                    Poll::Ready(Some(work)) => self.take(work),
                    Poll::Ready(None) => open = false,
                    Poll::Pending => break,
                }
            }
            if generation.is_some_and(|generation| self.cancelled.contains(&generation)) {
                return Poll::Ready(None);
            }
            call.as_mut().poll(cx).map(Some)
        })
        .await
    }
}

/// A spoken answer's audio as one PCM frame of its generation: mono 16-bit
/// PCM in a WAV, at the rate its header says.
fn spoken_frame(generation: GenerationEpoch, response: &MediaResponse) -> Result<PcmFrame> {
    let bytes = response
        .parts
        .iter()
        .find_map(|part| match part {
            MediaPart::Audio { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| invalid("speech returned no audio"))?;
    let clip = WavClip::parse(bytes)
        .filter(|clip| clip.is_pcm16() && clip.channels == 1)
        .ok_or_else(|| invalid("speech audio is not mono PCM16 WAV"))?;
    if clip.data.is_empty() || !clip.data.len().is_multiple_of(2) {
        return Err(invalid("speech audio has no whole samples"));
    }
    Ok(PcmFrame {
        generation,
        sample_rate: clip.sample_rate,
        samples: clip
            .data
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    })
}

/// A transcription's answer as one ASR event: its text as a final, or an
/// endpoint when the utterance said nothing.
fn heard(response: &MediaResponse, latency_ms: f64) -> AsrEvent {
    let text = response
        .parts
        .iter()
        .filter_map(|part| match part {
            MediaPart::Text { text } => Some(text.trim()),
            _ => None,
        })
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    AsrEvent {
        kind: if text.is_empty() {
            AsrEventKind::Endpoint
        } else {
            AsrEventKind::Final
        },
        text,
        tokens: Vec::new(),
        provider_latency_ms: Some(latency_ms),
        endpoint_delay_ms: None,
        error: None,
    }
}

fn asr_error(error: String) -> AsrEvent {
    AsrEvent {
        kind: AsrEventKind::Error,
        text: String::new(),
        tokens: Vec::new(),
        provider_latency_ms: None,
        endpoint_delay_ms: None,
        error: Some(error),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Open,
    Ended,
    CancelPending,
    Cancelled,
}

/// The cascade's TTS port on a speech route. One adapter owns one
/// generation; each flushed sentence is one `ai.speech` call.
pub struct MediaTtsAdapter<Q> {
    vault: Arc<Vault>,
    route: MediaVoiceRoute,
    render: VoiceRender,
    queue: Q,
    binding: Option<BankVoiceBinding>,
    generation: Option<GenerationEpoch>,
    phase: Phase,
    buffer: String,
    next_submission: u64,
}

impl<Q: VoiceMediaQueue> MediaTtsAdapter<Q> {
    pub fn new(
        vault: Arc<Vault>,
        route: MediaVoiceRoute,
        render: VoiceRender,
        queue: Q,
    ) -> Result<Self> {
        if route.operation() != AiOperation::Speech {
            return Err(invalid("a TTS adapter speaks on a speech route"));
        }
        if let VoiceRender::Stock(name) = &render
            && name.trim().is_empty()
        {
            return Err(invalid("a stock voice has a name"));
        }
        Ok(Self {
            vault,
            route,
            render,
            queue,
            binding: None,
            generation: None,
            phase: Phase::Fresh,
            buffer: String::new(),
            next_submission: 0,
        })
    }

    /// The banked clone this generation renders as, once started.
    #[must_use]
    pub fn binding(&self) -> Option<&BankVoiceBinding> {
        self.binding.as_ref()
    }

    /// Closes output for good; the queued and in-flight speech is dropped
    /// when the cancel goes. A failed cancel stays retryable.
    fn revoke(&mut self, generation: GenerationEpoch) {
        self.phase = Phase::CancelPending;
        self.buffer.clear();
        if self
            .queue
            .try_submit(VoiceMediaWork::Cancel { generation })
            .is_ok()
        {
            self.phase = Phase::Cancelled;
        }
    }

    fn flush(&mut self, generation: GenerationEpoch) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if let Some(binding) = &self.binding
            && !binding.is_current(&self.vault)
        {
            self.revoke(generation);
            return Err(invalid("voice withdrawn, evicted or stale"));
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let voice = match &self.render {
            VoiceRender::Stock(name) => Some(MediaVoice::Stock { name: name.clone() }),
            VoiceRender::Bank { .. } => self.binding.as_ref().map(BankVoiceBinding::voice),
        };
        let request = self.route.request(
            MediaPart::Text {
                text: self.buffer.clone(),
            },
            voice,
        );
        // A queue refusal admits nothing and keeps the sentence for retry.
        self.queue.try_submit(VoiceMediaWork::Speech {
            generation,
            submission: self.next_submission,
            request,
            voice: self.binding.clone(),
        })?;
        self.next_submission = next;
        self.buffer.clear();
        Ok(())
    }
}

impl<Q: VoiceMediaQueue> TtsSeamClient for MediaTtsAdapter<Q> {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if matches!(command, TtsCommand::Start { .. }) {
            if self.phase != Phase::Fresh {
                return Err(invalid("adapter is single-generation"));
            }
            // A banked voice binds before any word: no clone, no speech.
            self.binding = match &self.render {
                VoiceRender::Stock(_) => None,
                VoiceRender::Bank {
                    voice_id, register, ..
                } if self.route.reference_target => Some(BankVoiceBinding::bind_reference(
                    &self.vault,
                    voice_id,
                    &self.route.target,
                    register.as_deref(),
                    self.route.locality,
                )?),
                VoiceRender::Bank {
                    voice_id,
                    include_generated,
                    ..
                } => Some(BankVoiceBinding::bind(
                    &self.vault,
                    voice_id,
                    &self.route.target,
                    *include_generated,
                    self.route.locality,
                )?),
            };
            self.generation = Some(generation);
            self.phase = Phase::Open;
            return Ok(());
        }
        if matches!(command, TtsCommand::Cancel { .. }) {
            if self.phase == Phase::Fresh {
                self.generation = Some(generation);
            }
            if self.generation != Some(generation) {
                return Err(invalid("unmatched generation"));
            }
            if self.phase != Phase::Cancelled {
                self.phase = Phase::CancelPending; // fail closed even if dispatch fails
                self.buffer.clear();
                self.queue
                    .try_submit(VoiceMediaWork::Cancel { generation })?;
                self.phase = Phase::Cancelled;
            }
            return Ok(());
        }
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        if self.phase == Phase::Ended
            && matches!(command, TtsCommand::End { .. } | TtsCommand::Flush { .. })
        {
            return Ok(());
        }
        if self.phase != Phase::Open {
            return Err(invalid("input closed"));
        }
        match command {
            TtsCommand::Text { text, .. } => {
                if text.is_empty()
                    || text.len() > MAX_SENTENCE_BYTES.saturating_sub(self.buffer.len())
                {
                    return Err(invalid("empty or oversized text"));
                }
                self.buffer.push_str(&text);
            }
            TtsCommand::Flush { .. } => self.flush(generation)?,
            TtsCommand::End { .. } => {
                self.flush(generation)?;
                self.phase = Phase::Ended;
            }
            TtsCommand::Start { .. } | TtsCommand::Cancel { .. } => {
                unreachable!("Start and Cancel handled above")
            }
        }
        Ok(())
    }
}

/// The cascade's ASR port on a transcription route. It buffers the host's
/// PCM16LE and sends each cut utterance as one `ai.transcribe` call, in a
/// WAV of the stream's rate and channels.
pub struct MediaAsrAdapter<Q> {
    route: MediaVoiceRoute,
    queue: Q,
    sample_rate: u32,
    channels: u16,
    buffer: Vec<u8>,
    next_submission: u64,
    ended: bool,
}

impl<Q: VoiceMediaQueue> MediaAsrAdapter<Q> {
    /// `sample_rate` and `channels` describe the PCM16LE the host hands to
    /// `accept_audio`.
    pub fn new(route: MediaVoiceRoute, sample_rate: u32, channels: u16, queue: Q) -> Result<Self> {
        if route.operation() != AiOperation::Transcribe {
            return Err(invalid("an ASR adapter hears on a transcription route"));
        }
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        Ok(Self {
            route,
            queue,
            sample_rate,
            channels,
            buffer: Vec::new(),
            next_submission: 0,
            ended: false,
        })
    }

    fn max_bytes(&self) -> usize {
        let per_second = u64::from(self.sample_rate) * u64::from(self.channels) * 2;
        usize::try_from(per_second * u64::from(MAX_UTTERANCE_SECONDS)).unwrap_or(usize::MAX)
    }

    /// Sends what was heard since the last cut as one transcription call:
    /// the host's VAD or turn detector marks an utterance's end here. The
    /// answer comes back as [`VoiceMediaOutput::Heard`] with the returned
    /// submission; an empty cut sends nothing. A refused queue keeps the
    /// audio for retry.
    pub fn cut(&mut self) -> Result<Option<u64>> {
        let block = usize::from(self.channels) * 2;
        let whole = self.buffer.len() - self.buffer.len() % block;
        if whole == 0 {
            return Ok(None);
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let wav = pcm16_wav(self.sample_rate, self.channels, &self.buffer[..whole])
            .ok_or_else(|| invalid("utterance too long"))?;
        let request = self.route.request(
            MediaPart::Audio {
                media_type: "audio/wav".into(),
                bytes: wav,
            },
            None,
        );
        let submission = self.next_submission;
        self.queue.try_submit(VoiceMediaWork::Transcribe {
            submission,
            request,
        })?;
        self.next_submission = next;
        // A trailing half-sample waits for the bytes that complete it.
        self.buffer.drain(..whole);
        Ok(Some(submission))
    }
}

impl<Q: VoiceMediaQueue> AsrStream for MediaAsrAdapter<Q> {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()> {
        if self.ended {
            return Err(invalid("audio after end"));
        }
        if pcm.len() > self.max_bytes().saturating_sub(self.buffer.len()) {
            return Err(invalid("utterance too long; cut it sooner"));
        }
        self.buffer.extend_from_slice(pcm);
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.cut()?;
        self.ended = true;
        self.buffer.clear();
        Ok(())
    }
}

impl MediaVoiceRoute {
    /// The admission request of one bounded live stream on a transcription
    /// route: the route's call with no audio yet, naming the PCM16LE the
    /// stream carries. Its audio is admitted as it goes, on the stream's
    /// lease ([`LeasedAsrStream`]).
    pub fn stream_request(&self, sample_rate: u32, channels: u16) -> Result<MediaRequest> {
        if self.operation() != AiOperation::Transcribe {
            return Err(invalid("a live stream hears on a transcription route"));
        }
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        let mut request = self.request(
            MediaPart::Audio {
                media_type: "audio/pcm".into(),
                bytes: Vec::new(),
            },
            None,
        );
        request
            .params
            .insert("audio_format".to_owned(), "pcm_s16le".into());
        request
            .params
            .insert("sample_rate".to_owned(), sample_rate.into());
        request
            .params
            .insert("num_channels".to_owned(), channels.into());
        Ok(request)
    }
}

/// The host's door for one bounded live stream: it admits the stream on
/// the route's rung under a run of its own, on one permit that reserves
/// `bound_ms` of audio, and starts it at the rung's media gate before any
/// audio leaves.
pub trait VoiceStreamDoor: Send + Sync {
    fn open_stream<'a>(
        &'a self,
        request: MediaRequest,
        bound_ms: u64,
    ) -> MediaFuture<'a, MediaStreamLease>;
}

/// A live ASR stream (Soniox partials) on one bounded stream lease. Each
/// chunk of the host's PCM16LE is metered on the lease before the inner
/// stream sends it, so audio past the bound never leaves; the stream
/// settles the audio it admitted when it ends, and when it is cancelled or
/// dropped. The inner stream's provider frames are read through
/// [`Self::inner_mut`].
pub struct LeasedAsrStream<S> {
    inner: S,
    lease: Option<MediaStreamLease>,
    sample_rate: u32,
    channels: u16,
    bytes: u64,
}

impl<S: AsrStream> LeasedAsrStream<S> {
    /// `sample_rate` and `channels` describe the PCM16LE the host hands to
    /// `accept_audio`, as the stream's request named them.
    pub fn new(inner: S, lease: MediaStreamLease, sample_rate: u32, channels: u16) -> Result<Self> {
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        Ok(Self {
            inner,
            lease: Some(lease),
            sample_rate,
            channels,
            bytes: 0,
        })
    }

    /// Opens one bounded stream on `route` through `door`, and wraps
    /// `inner`, the provider's stream, in its lease.
    pub async fn open(
        door: &dyn VoiceStreamDoor,
        route: &MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
        inner: S,
    ) -> Result<Self> {
        let request = route.stream_request(sample_rate, channels)?;
        let lease = door
            .open_stream(request, MAX_STREAM_AUDIO_MS)
            .await
            .map_err(|error| Error::InvalidConfig(format!("voice media: {error}")))?;
        Self::new(inner, lease, sample_rate, channels)
    }

    /// The provider's stream, for the frames it hands back.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The audio the stream may still carry, in milliseconds; 0 once it
    /// ended.
    #[must_use]
    pub fn remaining_ms(&self) -> u64 {
        self.lease
            .as_ref()
            .map_or(0, MediaStreamLease::remaining_ms)
    }

    /// Stops the stream: the audio it sent is paid for, and no more leaves.
    pub fn cancel(&mut self) -> Result<()> {
        match self.lease.take() {
            Some(lease) => lease.cancel().map(drop).map_err(settlement),
            None => Ok(()),
        }
    }

    /// The whole milliseconds `bytes` of the stream's PCM16LE play for,
    /// rounded up.
    fn played_ms(&self, bytes: u64) -> u64 {
        let per_second = u64::from(self.sample_rate) * u64::from(self.channels) * 2;
        bytes.saturating_mul(1_000).div_ceil(per_second.max(1))
    }
}

impl<S: AsrStream> AsrStream for LeasedAsrStream<S> {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()> {
        let bytes = self
            .bytes
            .checked_add(pcm.len() as u64)
            .ok_or_else(|| invalid("stream exhausted"))?;
        let played = self.played_ms(bytes);
        let lease = self
            .lease
            .as_mut()
            .ok_or_else(|| invalid("audio after end"))?;
        // Metered before it leaves: audio the lease refuses is never sent.
        lease
            .admit_audio(played.saturating_sub(lease.admitted_ms()))
            .map_err(|_| invalid("stream bound reached; end it and open the next"))?;
        self.bytes = bytes;
        self.inner.accept_audio(pcm)
    }

    fn end(&mut self) -> Result<()> {
        let Some(lease) = self.lease.take() else {
            return Ok(());
        };
        match self.inner.end() {
            Ok(()) => lease.end(None).map(drop).map_err(settlement),
            Err(error) => {
                // The refusal, if any, is on the Settled receipt.
                lease.cancel().ok();
                Err(error)
            }
        }
    }
}

fn settlement(denied: crate::llm::run_admission::RunDenied) -> Error {
    Error::InvalidConfig(format!("voice media: stream settlement refused: {denied}"))
}
