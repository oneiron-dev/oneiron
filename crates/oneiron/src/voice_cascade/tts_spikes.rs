//! Experimental Irodori/MOSS-local submission and PCM normalization only.
//! No model loading, provider SDK, HTTP, runner, persistence or latency measurement.
//! Hosts supply concrete pins, boot identity, capabilities and a bounded queue. These
//! are host assertions, not verified installation/boot evidence. Queue calls run outside
//! the cascade session lock; scheduling and model/network work stay with the host.
//! Released endpoints are NOT assumed incremental. Buffered responses are never sliced.
//! Each adapter owns one generation. The cascade alone owns epoch policy: forward PCM
//! through `filter_pcm` and recheck at playback. Hosts dispatch cancellation and discard
//! queued audio on stop. Dropping an adapter cannot cancel remote work.

use std::collections::VecDeque;

use crate::error::{Error, Result};

use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession};

pub const MAX_TEXT_BYTES: usize = 8 * 1024;
pub const MAX_VOICE_BYTES: usize = 4096;
pub const MAX_PCM_BYTES: usize = 2 * 1024 * 1024;
const MAX_PIN_BYTES: usize = 512;
const MAX_PENDING_RESPONSES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Irodori,
    MossLocal,
}

impl Provider {
    #[must_use]
    pub fn model(self) -> &'static str {
        match self {
            Self::Irodori => "Irodori-TTS-600M-v3-VoiceDesign",
            Self::MossLocal => "MOSS-TTS-Local-Transformer-v1.5",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingCapability {
    RequestBuffered,
    /// Host attests negotiation with this pinned runtime, not a model-name guess.
    Incremental {
        runtime_negotiation: String,
    },
}

/// Required concrete host pins. No default coordinates or implicit downloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePins {
    pub checkpoint: String,
    pub runtime: String,
    /// Host-reported boot identity; this adapter does not observe a runtime boot.
    pub boot_id: String,
}

/// Ephemeral, host-resolved references, subject to host access/consent gates. Never
/// supply audio/encoded audio, credentials or secret URLs. No loading or serialization.
#[derive(Clone, PartialEq, Eq)]
pub enum VoiceReference {
    CompanionMetadata {
        reference_id: String,
        transcript: Option<String>,
        language: Option<String>,
    },
    /// Non-secret token into host-owned runtime state, not a bearer credential.
    RuntimeHandle(String),
}

/// Typed constructor input; no optional-key parser or persisted voice schema here.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct VoiceContext {
    pub reference: Option<VoiceReference>,
    pub register: Option<String>,
    pub caption: Option<String>,
    pub nonverbal_tags: Vec<String>,
    pub seed: Option<u64>,
}

#[derive(Clone)]
pub struct ProviderConfig {
    pub pins: RuntimePins,
    /// Actual mono PCM16 output rate promised by the pinned host runtime.
    pub sample_rate: u32,
    pub streaming: StreamingCapability,
    pub voice: VoiceContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub provider: Provider,
    pub model: &'static str,
    pub pins: RuntimePins,
    pub sample_rate: u32,
    pub streaming: StreamingCapability,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProviderOperation {
    Start {
        metadata: ProviderMetadata,
        voice: Box<VoiceContext>,
    },
    /// Only submitted with an explicit Incremental negotiation.
    Text(String),
    /// Some(text): one complete synthesis request. None: incremental boundary.
    Flush {
        buffered_text: Option<String>,
    },
    /// Atomically submit any final buffered text AND close input. None closes
    /// without synthesizing again. The host later reports generation-level done.
    End {
        buffered_text: Option<String>,
    },
    Cancel,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderWork {
    pub provider: Provider,
    pub generation: GenerationEpoch,
    /// Contiguous queue-admission sequence, starting at zero. Echo on buffered PCM.
    pub sequence: u64,
    pub operation: ProviderOperation,
}

/// Host-owned bounded queue, NOT a provider implementation. Return immediately;
/// never perform model/network work or create an orchestrator. Ok admits one FIFO
/// item; Err MUST admit nothing. Hosts own capacity, retries and provider invocation.
/// Start applies every voice control or reports UnsupportedConfiguration. Cancel
/// must also be idempotent at the runtime. Ambiguous queue acceptance is forbidden.
pub trait TransportQueue {
    fn try_submit(&mut self, work: ProviderWork) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDelivery {
    /// Entire unsliced response to this Flush/End submission, delivered in FIFO order.
    BufferedResponse { submission: u64 },
    /// A chunk actually emitted by the negotiated runtime, never WAV slicing.
    IncrementalChunk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioEncoding {
    Pcm16Le,
    Float32Le,
    Wav,
}

pub struct ProviderAudio<'a> {
    pub generation: GenerationEpoch,
    /// Contiguous output sequence across the generation, starting at zero.
    pub chunk_index: u64,
    pub delivery: AudioDelivery,
    pub sample_rate: u32,
    pub channels: u16,
    pub encoding: AudioEncoding,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOrigin {
    pub metadata: ProviderMetadata,
    pub delivery: AudioDelivery,
    pub chunk_index: u64,
}

/// One transient normalized result. The adapter retains no PCM queue.
#[must_use = "filter and forward PCM, or explicitly discard it"]
pub struct NormalizedPcm {
    frame: PcmFrame,
    pub origin: ProviderOrigin,
}

impl NormalizedPcm {
    /// The existing cascade is the authority, including session identity. Repeat
    /// that check at playback; local normalization is not permission to play audio.
    #[must_use]
    pub fn filter_pcm(self, session: &VoiceCascadeSession) -> Option<(PcmFrame, ProviderOrigin)> {
        session
            .filter_pcm(self.frame)
            .map(|frame| (frame, self.origin))
    }
}

/// Bounded, sanitized host error classification; raw provider errors stay with host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    RuntimeFailure,
    UnsupportedConfiguration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Open,
    Ended,
    CancelPending,
    Cancelled,
    Done,
    Failed,
}

struct Adapter<Q> {
    queue: Q,
    metadata: ProviderMetadata,
    voice: VoiceContext,
    generation: Option<GenerationEpoch>,
    phase: Phase,
    sequence: u64,
    chunk_index: u64,
    text_bytes: usize,
    buffer: String,
    dirty: bool,
    pending: VecDeque<u64>,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("experimental TTS: {message}"))
}

fn bounded(value: &str, limit: usize) -> Result<()> {
    if value.len() > limit || value.trim().is_empty() {
        return Err(invalid("empty or oversized configuration field"));
    }
    Ok(())
}

impl ProviderConfig {
    fn validate(&self) -> Result<()> {
        for pin in [
            &self.pins.checkpoint,
            &self.pins.runtime,
            &self.pins.boot_id,
        ] {
            bounded(pin, MAX_PIN_BYTES)?;
        }
        if !(8000..=192_000).contains(&self.sample_rate) {
            return Err(invalid("unsupported output rate bound"));
        }
        if let StreamingCapability::Incremental {
            runtime_negotiation,
        } = &self.streaming
        {
            bounded(runtime_negotiation, MAX_PIN_BYTES)?;
        }
        if self.voice.nonverbal_tags.len() > 16 {
            return Err(invalid("too many nonverbal tags"));
        }
        let mut remaining = MAX_VOICE_BYTES;
        let mut field = |value: &str| -> Result<()> {
            bounded(value, remaining)?;
            remaining -= value.len();
            Ok(())
        };
        match &self.voice.reference {
            Some(VoiceReference::CompanionMetadata {
                reference_id,
                transcript,
                language,
            }) => {
                field(reference_id)?;
                for value in transcript.iter().chain(language.iter()) {
                    field(value)?;
                }
            }
            Some(VoiceReference::RuntimeHandle(handle)) => field(handle)?,
            None => {}
        }
        for value in self.voice.register.iter().chain(self.voice.caption.iter()) {
            field(value)?;
        }
        for tag in &self.voice.nonverbal_tags {
            bounded(tag, 128)?;
            field(tag)?;
        }
        Ok(())
    }
}

impl<Q: TransportQueue> Adapter<Q> {
    fn new(provider: Provider, config: ProviderConfig, queue: Q) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            queue,
            metadata: ProviderMetadata {
                provider,
                model: provider.model(),
                pins: config.pins,
                sample_rate: config.sample_rate,
                streaming: config.streaming,
            },
            voice: config.voice,
            generation: None,
            phase: Phase::Fresh,
            sequence: 0,
            chunk_index: 0,
            text_bytes: 0,
            buffer: String::new(),
            dirty: false,
            pending: VecDeque::new(),
        })
    }

    fn buffered(&self) -> bool {
        self.metadata.streaming == StreamingCapability::RequestBuffered
    }

    fn matched(&self, generation: GenerationEpoch) -> Result<()> {
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        Ok(())
    }

    fn send(&mut self, generation: GenerationEpoch, operation: ProviderOperation) -> Result<()> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        self.queue.try_submit(ProviderWork {
            provider: self.metadata.provider,
            generation,
            sequence: self.sequence,
            operation,
        })?;
        self.sequence = next;
        Ok(())
    }

    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if matches!(&command, TtsCommand::Start { .. }) {
            if self.phase != Phase::Fresh {
                return Err(invalid(
                    "adapter is single-generation; Start already consumed",
                ));
            }
            self.send(
                generation,
                ProviderOperation::Start {
                    metadata: self.metadata.clone(),
                    voice: Box::new(self.voice.clone()),
                },
            )?;
            self.generation = Some(generation);
            self.phase = Phase::Open;
            return Ok(());
        }
        if matches!(&command, TtsCommand::Cancel { .. }) {
            if self.phase == Phase::Fresh {
                self.generation = Some(generation);
            }
            self.matched(generation)?;
            if self.phase != Phase::Cancelled {
                // Fail closed BEFORE admission. Failure permits only a Cancel retry.
                self.phase = Phase::CancelPending;
                self.buffer.clear();
                self.pending.clear();
                self.dirty = false;
                self.send(generation, ProviderOperation::Cancel)?;
                self.phase = Phase::Cancelled;
            }
            return Ok(());
        }
        self.matched(generation)?;
        if matches!(self.phase, Phase::Ended | Phase::Done)
            && matches!(&command, TtsCommand::Flush { .. } | TtsCommand::End { .. })
        {
            return Ok(());
        }
        if self.phase != Phase::Open {
            return Err(invalid("input is not open"));
        }
        match command {
            TtsCommand::Text { text, .. } => {
                if text.is_empty() || text.len() > MAX_TEXT_BYTES - self.text_bytes {
                    return Err(invalid("empty text or generation text limit exceeded"));
                }
                let bytes = text.len();
                if self.buffered() {
                    self.buffer.push_str(&text);
                } else {
                    self.send(generation, ProviderOperation::Text(text))?;
                }
                self.text_bytes += bytes;
                self.dirty = true;
            }
            TtsCommand::Flush { .. } => self.boundary(generation, false)?,
            TtsCommand::End { .. } => self.boundary(generation, true)?,
            _ => unreachable!("Start and Cancel handled above"),
        }
        Ok(())
    }

    fn boundary(&mut self, generation: GenerationEpoch, end: bool) -> Result<()> {
        if !end && !self.dirty {
            return Ok(());
        }
        let has_response = self.buffered() && !self.buffer.is_empty();
        if has_response && self.pending.len() == MAX_PENDING_RESPONSES {
            return Err(invalid(
                "buffered responses must drain before more submission",
            ));
        }
        let buffered_text = has_response.then(|| self.buffer.clone());
        let operation = if end {
            ProviderOperation::End { buffered_text }
        } else {
            ProviderOperation::Flush { buffered_text }
        };
        let sequence = self.sequence;
        self.send(generation, operation)?;
        if has_response {
            self.pending.push_back(sequence);
        }
        self.buffer.clear();
        self.dirty = false;
        if end {
            self.phase = Phase::Ended;
        }
        Ok(())
    }

    fn handle_pcm(&mut self, audio: ProviderAudio<'_>) -> Result<NormalizedPcm> {
        self.matched(audio.generation)?;
        if !matches!(self.phase, Phase::Open | Phase::Ended) || self.text_bytes == 0 {
            return Err(invalid("output is not open"));
        }
        if audio.chunk_index != self.chunk_index {
            return Err(invalid("duplicate or out-of-order PCM"));
        }
        match (&self.metadata.streaming, audio.delivery) {
            (
                StreamingCapability::RequestBuffered,
                AudioDelivery::BufferedResponse { submission },
            ) if self.pending.front() == Some(&submission) => {}
            (StreamingCapability::Incremental { .. }, AudioDelivery::IncrementalChunk) => {}
            _ => {
                return Err(invalid(
                    "unmatched response or unnegotiated streaming claim",
                ));
            }
        }
        if audio.sample_rate != self.metadata.sample_rate
            || audio.channels != 1
            || audio.encoding != AudioEncoding::Pcm16Le
            || audio.bytes.is_empty()
            || audio.bytes.len() > MAX_PCM_BYTES
            || !audio.bytes.len().is_multiple_of(2)
        {
            return Err(invalid(
                "expected bounded mono PCM16LE at the configured rate",
            ));
        }
        let next = self
            .chunk_index
            .checked_add(1)
            .ok_or_else(|| invalid("PCM sequence exhausted"))?;
        let samples = audio
            .bytes
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        self.chunk_index = next;
        if self.buffered() {
            self.pending.pop_front();
        }
        Ok(NormalizedPcm {
            frame: PcmFrame {
                generation: audio.generation,
                sample_rate: audio.sample_rate,
                samples,
            },
            origin: ProviderOrigin {
                metadata: self.metadata.clone(),
                delivery: audio.delivery,
                chunk_index: audio.chunk_index,
            },
        })
    }

    fn handle_done(&mut self, generation: GenerationEpoch) -> Result<()> {
        self.matched(generation)?;
        if self.phase == Phase::Done {
            return Ok(());
        }
        if self.phase != Phase::Ended || !self.pending.is_empty() {
            return Err(invalid(
                "done before End/responses, or after cancellation/failure",
            ));
        }
        self.phase = Phase::Done;
        Ok(())
    }

    fn handle_error(
        &mut self,
        generation: GenerationEpoch,
        failure: ProviderFailure,
    ) -> Result<ProviderFailure> {
        self.matched(generation)?;
        if !matches!(self.phase, Phase::Open | Phase::Ended) {
            return Err(invalid("error for inactive request"));
        }
        self.phase = Phase::Failed;
        self.buffer.clear();
        self.pending.clear();
        self.dirty = false;
        Ok(failure)
    }
}

macro_rules! adapter {
    ($name:ident, $provider:expr) => {
        /// Single-generation experimental adapter. Queue admission is its only side effect.
        pub struct $name<Q>(Adapter<Q>);

        impl<Q: TransportQueue> $name<Q> {
            pub fn new(config: ProviderConfig, queue: Q) -> Result<Self> {
                Adapter::new($provider, config, queue).map(Self)
            }

            #[must_use]
            pub fn metadata(&self) -> &ProviderMetadata {
                &self.0.metadata
            }

            /// Supply a real runtime result; no PCM is retained by the adapter.
            pub fn handle_pcm(&mut self, audio: ProviderAudio<'_>) -> Result<NormalizedPcm> {
                self.0.handle_pcm(audio)
            }

            /// Generation-level runtime completion, NOT a playback-drained acknowledgement.
            pub fn handle_done(&mut self, generation: GenerationEpoch) -> Result<()> {
                self.0.handle_done(generation)
            }

            /// Host must surface the failure and stop/discard its queued output.
            pub fn handle_error(
                &mut self,
                generation: GenerationEpoch,
                failure: ProviderFailure,
            ) -> Result<ProviderFailure> {
                self.0.handle_error(generation, failure)
            }
        }

        impl<Q: TransportQueue> TtsSeamClient for $name<Q> {
            fn submit(&mut self, command: TtsCommand) -> Result<()> {
                self.0.submit(command)
            }
        }
    };
}

adapter!(IrodoriAdapter, Provider::Irodori);
adapter!(MossLocalAdapter, Provider::MossLocal);

#[cfg(test)]
mod tests {
    use super::*;

    // Captured queue traffic and fixture PCM are unit evidence, not runtime proof.
    #[derive(Default)]
    struct Capture {
        commands: Vec<ProviderWork>,
        fail_next: bool,
    }

    impl TransportQueue for Capture {
        fn try_submit(&mut self, work: ProviderWork) -> Result<()> {
            if std::mem::take(&mut self.fail_next) {
                return Err(invalid("unit queue full: nothing admitted"));
            }
            self.commands.push(work);
            Ok(())
        }
    }

    fn epoch(session: u128) -> GenerationEpoch {
        GenerationEpoch {
            session: uuid::Uuid::from_u128(session),
            value: 1,
        }
    }

    fn config(incremental: bool) -> ProviderConfig {
        ProviderConfig {
            pins: RuntimePins {
                checkpoint: "unit-checkpoint-not-live".into(),
                runtime: "unit-runtime-not-live".into(),
                boot_id: "unit-boot-not-observed".into(),
            },
            sample_rate: 24_000,
            streaming: if incremental {
                StreamingCapability::Incremental {
                    runtime_negotiation: "unit-handshake".into(),
                }
            } else {
                StreamingCapability::RequestBuffered
            },
            voice: VoiceContext::default(),
        }
    }

    fn open(provider: Provider, incremental: bool) -> Adapter<Capture> {
        let mut a = Adapter::new(provider, config(incremental), Capture::default()).unwrap();
        let generation = epoch(1);
        a.submit(TtsCommand::Start { generation }).unwrap();
        a
    }

    fn text(a: &mut Adapter<Capture>, text: &str) -> Result<()> {
        a.submit(TtsCommand::Text {
            generation: epoch(1),
            text: text.into(),
        })
    }

    fn audio<'a>(delivery: AudioDelivery) -> ProviderAudio<'a> {
        ProviderAudio {
            generation: epoch(1),
            chunk_index: 0,
            delivery,
            sample_rate: 24_000,
            channels: 1,
            encoding: AudioEncoding::Pcm16Le,
            bytes: &[1, 0, 255, 255],
        }
    }

    #[test]
    fn concrete_models_forward_voice_pins_and_session_identity() {
        let mut c = config(false);
        c.voice.reference = Some(VoiceReference::CompanionMetadata {
            reference_id: "unit-reference".into(),
            transcript: Some("unit transcript".into()),
            language: Some("ja".into()),
        });
        c.voice.register = Some("unit-register".into());
        c.voice.caption = Some("unit-caption".into());
        c.voice.nonverbal_tags.push("unit-tag".into());
        c.voice.seed = Some(7);
        let mut i = IrodoriAdapter::new(c.clone(), Capture::default()).unwrap();
        let mut m = MossLocalAdapter::new(c.clone(), Capture::default()).unwrap();
        assert_eq!(i.metadata().model, "Irodori-TTS-600M-v3-VoiceDesign");
        assert_eq!(m.metadata().model, "MOSS-TTS-Local-Transformer-v1.5");
        let generation = epoch(9);
        i.submit(TtsCommand::Start { generation }).unwrap();
        m.submit(TtsCommand::Start { generation }).unwrap();
        for a in [&i.0, &m.0] {
            let work = &a.queue.commands[0];
            assert_eq!(work.generation, generation);
            assert_eq!(a.metadata.pins, c.pins);
            assert!(
                work.operation
                    == ProviderOperation::Start {
                        metadata: a.metadata.clone(),
                        voice: Box::new(c.voice.clone()),
                    }
            );
        }
    }

    #[test]
    fn both_modes_buffer_or_submit_text_and_never_repeat_boundaries() {
        for provider in [Provider::Irodori, Provider::MossLocal] {
            for incremental in [false, true] {
                let mut a = open(provider, incremental);
                let generation = epoch(1);
                text(&mut a, "one").unwrap();
                text(&mut a, " two").unwrap();
                assert_eq!(a.queue.commands.len(), if incremental { 3 } else { 1 });
                if incremental {
                    assert!(a.queue.commands[1].operation == ProviderOperation::Text("one".into()));
                }
                for command in [
                    TtsCommand::Flush { generation },
                    TtsCommand::End { generation },
                ] {
                    let count = a.queue.commands.len();
                    a.queue.fail_next = true;
                    assert!(a.submit(command.clone()).is_err());
                    assert_eq!(a.queue.commands.len(), count);
                    a.submit(command.clone()).unwrap();
                    let buffered_text = (!incremental).then(|| "one two".to_owned());
                    let expected = match command {
                        TtsCommand::Flush { .. } => ProviderOperation::Flush { buffered_text },
                        _ => ProviderOperation::End { buffered_text },
                    };
                    assert!(a.queue.commands.last().unwrap().operation == expected);
                    a.submit(command).unwrap();
                    assert_eq!(a.queue.commands.len(), count + 1);
                    if a.phase == Phase::Open {
                        text(&mut a, "one two").unwrap();
                    }
                }
                assert!(text(&mut a, "late").is_err());
                a.submit(TtsCommand::Flush { generation }).unwrap();
                for (index, work) in a.queue.commands.iter().enumerate() {
                    assert_eq!(work.sequence, index as u64);
                }
            }
        }
    }

    #[test]
    fn text_voice_negotiation_and_pending_responses_are_bounded() {
        for incremental in [false, true] {
            let mut a = open(Provider::Irodori, incremental);
            text(&mut a, &"x".repeat(MAX_TEXT_BYTES)).unwrap();
            a.submit(TtsCommand::Flush {
                generation: epoch(1),
            })
            .unwrap();
            assert!(text(&mut a, "é").is_err());
        }
        let mut c = config(false);
        c.voice.reference = Some(VoiceReference::RuntimeHandle("x".repeat(MAX_VOICE_BYTES)));
        assert!(MossLocalAdapter::new(c.clone(), Capture::default()).is_ok());
        c.voice.caption = Some("overflow".into());
        assert!(MossLocalAdapter::new(c, Capture::default()).is_err());
        let mut c = config(true);
        c.streaming = StreamingCapability::Incremental {
            runtime_negotiation: " ".into(),
        };
        assert!(IrodoriAdapter::new(c, Capture::default()).is_err());
        let mut c = config(false);
        c.pins.checkpoint.clear();
        assert!(IrodoriAdapter::new(c, Capture::default()).is_err());
        let mut a = open(Provider::MossLocal, false);
        for _ in 0..MAX_PENDING_RESPONSES {
            text(&mut a, "x").unwrap();
            a.submit(TtsCommand::Flush {
                generation: epoch(1),
            })
            .unwrap();
        }
        text(&mut a, "pending").unwrap();
        assert!(
            a.submit(TtsCommand::End {
                generation: epoch(1)
            })
            .is_err()
        );
        assert_eq!(a.buffer, "pending");
    }

    #[test]
    fn start_text_and_cancel_admission_failures_are_retry_safe_and_fail_closed() {
        let mut a = Adapter::new(Provider::MossLocal, config(true), Capture::default()).unwrap();
        let generation = epoch(1);
        assert!(text(&mut a, "before Start").is_err());
        a.queue.fail_next = true;
        assert!(a.submit(TtsCommand::Start { generation }).is_err());
        assert!(a.generation.is_none());
        a.submit(TtsCommand::Start { generation }).unwrap();
        a.queue.fail_next = true;
        assert!(text(&mut a, "retry").is_err());
        assert_eq!(a.text_bytes, 0);
        text(&mut a, "retry").unwrap();
        assert_eq!(generation.value(), epoch(2).value());
        assert!(
            a.submit(TtsCommand::Cancel {
                generation: epoch(2)
            })
            .is_err()
        );
        a.queue.fail_next = true;
        assert!(a.submit(TtsCommand::Cancel { generation }).is_err());
        assert!(
            a.handle_pcm(audio(AudioDelivery::IncrementalChunk))
                .is_err()
        );
        assert!(text(&mut a, "late").is_err());
        a.submit(TtsCommand::Cancel { generation }).unwrap();
        a.submit(TtsCommand::Cancel { generation }).unwrap();
        assert_eq!(a.queue.commands.len(), 3);
        assert!(a.handle_done(generation).is_err());
        assert!(
            a.handle_error(generation, ProviderFailure::RuntimeFailure)
                .is_err()
        );
        assert!(a.submit(TtsCommand::Start { generation }).is_err());
    }

    #[test]
    fn provider_callbacks_check_pcm_identity_order_and_mode_without_slicing() {
        for provider in [Provider::Irodori, Provider::MossLocal] {
            for incremental in [false, true] {
                let mut a = open(provider, incremental);
                let generation = epoch(1);
                text(&mut a, "unit text").unwrap();
                let delivery = if incremental {
                    AudioDelivery::IncrementalChunk
                } else {
                    AudioDelivery::BufferedResponse { submission: 1 }
                };
                if !incremental {
                    a.submit(TtsCommand::End { generation }).unwrap();
                }
                let oversized = vec![0; MAX_PCM_BYTES + 2];
                for bad in 0..10 {
                    let mut input = audio(delivery);
                    match bad {
                        0 => input.generation = epoch(2),
                        1 => input.sample_rate = 48_000,
                        2 => input.bytes = &[0],
                        3 => input.channels = 2,
                        4 => input.encoding = AudioEncoding::Wav,
                        5 => input.encoding = AudioEncoding::Float32Le,
                        6 => input.bytes = &[],
                        7 => input.chunk_index = 1,
                        8 => input.bytes = &oversized,
                        _ => input.delivery = AudioDelivery::BufferedResponse { submission: 99 },
                    }
                    assert!(a.handle_pcm(input).is_err());
                }
                if !incremental {
                    assert!(
                        a.handle_pcm(audio(AudioDelivery::IncrementalChunk))
                            .is_err()
                    );
                    assert!(a.handle_done(generation).is_err());
                }
                let pcm = a.handle_pcm(audio(delivery)).unwrap();
                assert_eq!(pcm.frame.generation, generation);
                assert_eq!(pcm.frame.samples, vec![1, -1]);
                assert_eq!(pcm.origin.delivery, delivery);
                assert_eq!(pcm.origin.metadata.streaming, config(incremental).streaming);
                assert!(a.handle_pcm(audio(delivery)).is_err());
                if incremental {
                    let mut next = audio(delivery);
                    next.chunk_index = 1;
                    assert_eq!(a.handle_pcm(next).unwrap().frame.samples, vec![1, -1]);
                }
                a.submit(TtsCommand::End { generation }).unwrap();
                a.handle_done(generation).unwrap();
                assert!(a.handle_pcm(audio(delivery)).is_err());
            }
        }
        let mut a = open(Provider::MossLocal, false);
        let failure = ProviderFailure::RuntimeFailure;
        assert!(a.handle_error(epoch(2), failure).is_err());
        assert_eq!(a.handle_error(epoch(1), failure).unwrap(), failure);
        assert!(text(&mut a, "late").is_err());
    }
}
