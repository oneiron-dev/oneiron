//! The cascade's speech and hearing on the host's media seats (OF-410).
//! [`MediaTtsAdapter`] and [`MediaAsrAdapter`] are the cascade's TTS and ASR
//! ports over `ai.speech` and `ai.transcribe`. Each SUBMITS work to a
//! [`VoiceMediaQueue`] and never waits; the queue never refuses it for room
//! or size (Rule 5). The host's [`VoiceMediaWorker`] runs that work outside
//! the session lock through its [`AiMediaDoor`], so every call is admitted
//! on its own permit, sent through its run's media gate and settled in its
//! native units (characters spoken, seconds heard), as every other media
//! call is.
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
//! utterance. A sentence past one call's text bound is spoken as several
//! calls, its audio joined in order; an utterance at one call's length is
//! cut there and the rest starts the next. Live partial transcripts
//! (Soniox) ride a [`LeasedAsrStream`] instead: one permit per bounded
//! stream, opened through the host's [`VoiceStreamDoor`], with each chunk of
//! audio metered on its lease before it leaves and the audio settled when
//! the stream ends or is cancelled.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Instant;

use tokio::sync::mpsc;

use super::{
    AsrEvent, AsrEventKind, AsrStream, GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient,
    speakable,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::llm::media::wav::{WavClip, pcm16_wav};
use crate::llm::media::{
    AiMediaDoor, AiOperation, MediaFuture, MediaPart, MediaRequest, MediaResponse, MediaVoice,
};
use crate::llm::run_admission::MediaStreamLease;
use crate::llm::{CallEnvelope, LlmResult, ModelId, ModelLocality, ModelTierRef, VoiceLane};
use crate::voice_identity::ref_bank::{VoiceRefFence, VoiceRegisterClip, VoiceRenderGrant};

mod asr;
mod routes;
mod stream;
mod tts;
mod worker;

/// The most text one spoken call carries: a flushed sentence, with room.
/// A longer one is spoken as several calls, its audio joined in order.
pub const MAX_SENTENCE_BYTES: usize = 8 * 1024;
/// The longest utterance one transcription call carries. The host cuts
/// sooner; audio past it is cut there and starts the next utterance.
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
/// nothing, and no call runs inside `try_submit`. No work is refused for
/// room (Rule 5), and a cancel goes ahead of queued work.
pub trait VoiceMediaQueue {
    fn try_submit(&mut self, work: VoiceMediaWork) -> Result<()>;
}

/// What the worker hands back to the host.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceMediaOutput {
    /// The cancelled epoch's queued speech and in-flight future are dropped.
    /// This is a server boundary, not a client playout acknowledgement.
    Cancelled { generation: GenerationEpoch },
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

/// A channel from adapters to one worker. Clone the sender for each
/// generation's adapter; the worker serves them all in order. `capacity` is
/// the pace a producer that waits keeps ([`VoiceMediaSender::has_room`]);
/// past it the queue still takes work (Rule 5: a full queue never refuses).
/// Cancels ride a lane of their own, so queued work never keeps a stop from
/// the worker.
#[must_use]
pub fn voice_media_channel(capacity: usize) -> (VoiceMediaSender, VoiceMediaWorker) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let (stop, stops) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    (
        VoiceMediaSender {
            work: sender,
            stop,
            queued: Arc::clone(&queued),
            capacity: capacity.max(1),
        },
        VoiceMediaWorker {
            work: receiver,
            stops,
            queued,
            pending: VecDeque::new(),
            cancelled: BTreeSet::new(),
            retired: Vec::new(),
        },
    )
}

#[derive(Clone)]
pub struct VoiceMediaSender {
    work: mpsc::UnboundedSender<VoiceMediaWork>,
    stop: mpsc::UnboundedSender<GenerationEpoch>,
    /// Items sent and not yet taken by the worker.
    queued: Arc<AtomicUsize>,
    capacity: usize,
}

/// Runs queued voice media work, in order, through the host's door.
pub struct VoiceMediaWorker {
    work: mpsc::UnboundedReceiver<VoiceMediaWork>,
    stops: mpsc::UnboundedReceiver<GenerationEpoch>,
    /// The senders' count of items not yet taken from `work`.
    queued: Arc<AtomicUsize>,
    pending: VecDeque<VoiceMediaWork>,
    cancelled: BTreeSet<GenerationEpoch>,
    retired: Vec<GenerationEpoch>,
}

/// A speech request whose text is past one call's bound, as one request per
/// piece in order; any other request as itself.
fn speech_pieces(request: MediaRequest) -> Vec<MediaRequest> {
    let text = match request.parts.as_slice() {
        [MediaPart::Text { text }] if text.len() > MAX_SENTENCE_BYTES => Some(text.clone()),
        _ => None,
    };
    let Some(text) = text else {
        return vec![request];
    };
    speakable::pieces(&text, MAX_SENTENCE_BYTES)
        .into_iter()
        .map(|piece| MediaRequest {
            parts: vec![MediaPart::Text {
                text: piece.to_owned(),
            }],
            ..request.clone()
        })
        .collect()
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
/// generation; each flushed sentence is one `ai.speech` call, or several
/// past [`MAX_SENTENCE_BYTES`].
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

fn settlement(denied: crate::llm::run_admission::RunDenied) -> Error {
    Error::InvalidConfig(format!("voice media: stream settlement refused: {denied}"))
}
