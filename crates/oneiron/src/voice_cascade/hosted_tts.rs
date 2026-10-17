//! Hosted TTS request adapters. A vault voice identity is the identity; provider
//! voice IDs are disposable render targets read from its bank target records. No
//! provisioning, credentials, network I/O, PCM buffering or provider selection
//! runs under the cascade lock.
//! Each render goes out as one `ai.speech` call on the host's media worker
//! ([`HostedMediaQueue`]): admitted on its own permit, sent through its run's
//! media gate to the hosted rung and settled on the characters it spoke, as
//! every other media call is. The rung owns the provider's wire; the host
//! hands each sentence's audio back and rechecks the epoch at playback.

use std::collections::VecDeque;

use super::media::{BankBound, BankVoiceBinding, MediaVoiceRoute, VoiceMediaQueue, VoiceMediaWork};
use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    llm::ModelLocality,
    llm::media::{AiOperation, MediaPart},
    voice_identity::ref_bank::VoiceRenderGrant,
};

pub const PCM_RATE: u32 = 24_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedProvider {
    Cartesia,
    ElevenLabsFlash,
}
impl HostedProvider {
    pub const fn target(self) -> &'static str {
        match self {
            Self::Cartesia => "cartesia",
            Self::ElevenLabsFlash => "elevenlabs_flash",
        }
    }
}

/// Provisioning (`Vault::prepare_voice_clone`, the vendor clone call, then
/// `Vault::record_voice_target_clone`) happens OUTSIDE this adapter. The vendor
/// voice ID is a provider-scoped, disposable locator, never the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedBinding {
    pub voice_id: String,
    pub owner: EntityId,
    pub provider: HostedProvider,
    pub vendor_voice_id: String,
    pub revision: [u8; 16],
    /// The render consent the clone is used under. Every hosted target is a
    /// third party's, so the voice's consent must reach that far.
    pub grant: VoiceRenderGrant,
}

/// One flushed sentence to render on the hosted target, in its banked clone.
/// No audio/ref clips, credentials or provider wire enter this DTO: the
/// hosted rung builds its own request.
#[derive(Debug, Clone, PartialEq)]
pub struct HostedRender {
    pub generation: GenerationEpoch,
    pub submission: u64,
    pub provider: HostedProvider,
    pub text: String,
    /// The clone it renders as, checked again before the call and before
    /// its audio is handed back.
    pub voice: BankVoiceBinding,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostedWork {
    Render(HostedRender),
    /// Host drops BOTH network work and all queued output before next dequeue.
    Cancel {
        generation: GenerationEpoch,
    },
}

/// FIFO, nonblocking, unambiguous admission. An error admits nothing.
/// Implementations never execute HTTP inside `try_submit`. A host's
/// transport is [`HostedMediaQueue`]: renders leave only as admitted media
/// calls.
pub trait HostedTransport {
    fn try_submit(&mut self, work: HostedWork) -> Result<()>;
}

/// The hosted adapter's transport on the media worker: each render is one
/// `ai.speech` call on `route`, the host's hosted rung for the target,
/// queued to the [`VoiceMediaWorker`](super::media::VoiceMediaWorker), whose
/// door admits, sends and settles it. A cancel drops the generation's queued
/// speech and its call in flight.
pub struct HostedMediaQueue<Q> {
    route: MediaVoiceRoute,
    queue: Q,
}

impl<Q: VoiceMediaQueue> HostedMediaQueue<Q> {
    /// `route` is the speech rung of a hosted target that keeps clones.
    pub fn new(route: MediaVoiceRoute, queue: Q) -> Result<Self> {
        if route.operation() != AiOperation::Speech
            || route.reference_target
            || route.locality != ModelLocality::ThirdParty
        {
            return Err(invalid("a hosted render goes on a hosted speech route"));
        }
        Ok(Self { route, queue })
    }
}

impl<Q: VoiceMediaQueue> HostedTransport for HostedMediaQueue<Q> {
    fn try_submit(&mut self, work: HostedWork) -> Result<()> {
        match work {
            HostedWork::Render(render) => {
                if render.provider.target() != self.route.target
                    || render.voice.target != self.route.target
                {
                    return Err(invalid("render target is not the route's"));
                }
                let request = self.route.request(
                    MediaPart::Text { text: render.text },
                    Some(render.voice.voice()),
                );
                self.queue.try_submit(VoiceMediaWork::Speech {
                    generation: render.generation,
                    submission: render.submission,
                    request,
                    voice: Some(render.voice),
                })
            }
            HostedWork::Cancel { generation } => {
                self.queue.try_submit(VoiceMediaWork::Cancel { generation })
            }
        }
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("hosted TTS: {message}"))
}

/// Bind a banked identity to its recorded voice on ONE hosted target.
/// `vault` remains the authority: an unprovisioned, evicted, stale or withdrawn
/// target cannot bind. This adapter does not retain the cloned reference audio.
pub struct HostedTtsAdapter<'v, T> {
    vault: &'v Vault,
    include_generated: bool,
    transport: T,
    binding: HostedBinding,
    generation: Option<GenerationEpoch>,
    phase: Phase,
    buffer: String,
    next_submission: u64,
    pending: VecDeque<PendingResponse>,
}
struct PendingResponse {
    submission: u64,
    next_chunk: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Open,
    Ended,
    CancelPending,
    Cancelled,
}

impl<'v, T: HostedTransport> HostedTtsAdapter<'v, T> {
    pub fn bind(
        vault: &'v Vault,
        voice_id: &str,
        provider: HostedProvider,
        include_generated: bool,
        transport: T,
    ) -> Result<Self> {
        let (record, grant) = vault
            .voice_target_clone(
                voice_id,
                provider.target(),
                include_generated,
                ModelLocality::ThirdParty,
            )?
            .ok_or_else(|| invalid("voice target not provisioned, evicted or stale"))?;
        // The ID is interpolated into a URL path: no separators, whitespace or
        // credentials. The bank's policy limit already bounds its length.
        if record.vendor_voice_id.is_empty()
            || !record
                .vendor_voice_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("vendor voice id is not URL-safe"));
        }
        // A withdrawal and recreation between these reads deletes the record,
        // so the revision fence refuses the first render of a mixed binding.
        let owner = vault
            .voice_identity(voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?
            .owner;
        Ok(Self {
            vault,
            include_generated,
            transport,
            binding: HostedBinding {
                voice_id: record.voice_id,
                owner,
                provider,
                vendor_voice_id: record.vendor_voice_id,
                revision: record.revision,
                grant,
            },
            generation: None,
            phase: Phase::Fresh,
            buffer: String::new(),
            next_submission: 0,
            pending: VecDeque::new(),
        })
    }

    pub fn binding(&self) -> &HostedBinding {
        &self.binding
    }

    fn request(&self, generation: GenerationEpoch, submission: u64) -> HostedRender {
        HostedRender {
            generation,
            submission,
            provider: self.binding.provider,
            text: self.buffer.clone(),
            voice: BankVoiceBinding {
                voice_id: self.binding.voice_id.clone(),
                target: self.binding.provider.target().to_owned(),
                include_generated: self.include_generated,
                bound: BankBound::Clone {
                    vendor_voice_id: self.binding.vendor_voice_id.clone(),
                    revision: self.binding.revision,
                    grant: self.binding.grant,
                },
            },
        }
    }

    fn revoke(&mut self, generation: GenerationEpoch) {
        self.phase = Phase::CancelPending;
        self.buffer.clear();
        self.pending.clear();
        // The caller still sees a refusal. A failed cancellation remains
        // retryable, while all local output and future admissions are closed.
        if self
            .transport
            .try_submit(HostedWork::Cancel { generation })
            .is_ok()
        {
            self.phase = Phase::Cancelled;
        }
    }

    fn ensure_live(&mut self, generation: GenerationEpoch) -> Result<crate::gate::HostedTtsLimits> {
        let live = self.vault.with_live_voice_target(
            &self.binding.voice_id,
            self.binding.provider.target(),
            self.include_generated,
            self.binding.revision,
            self.binding.grant,
            |txn| {
                crate::gate::resolve_hosted_tts_limits(
                    self.vault,
                    txn,
                    self.binding.provider.target(),
                    self.binding.owner,
                )
            },
        );
        match live {
            Ok(Some(limits)) => Ok(limits),
            Ok(None) => {
                self.revoke(generation);
                Err(invalid("voice target withdrawn, evicted or stale"))
            }
            Err(error) => {
                self.revoke(generation);
                Err(error)
            }
        }
    }

    fn flush(&mut self, generation: GenerationEpoch) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let request = self.request(generation, self.next_submission);
        // Serialize against the vault withdrawal writer through FIFO queue
        // admission; an LMDB read snapshot alone cannot do this.
        let admitted = self.vault.with_live_voice_target(
            &self.binding.voice_id,
            self.binding.provider.target(),
            self.include_generated,
            self.binding.revision,
            self.binding.grant,
            |txn| {
                let limits = crate::gate::resolve_hosted_tts_limits(
                    self.vault,
                    txn,
                    self.binding.provider.target(),
                    self.binding.owner,
                )?;
                if self.buffer.len() > limits.max_text_bytes {
                    return Err(invalid("policy text limit exceeded"));
                }
                self.transport.try_submit(HostedWork::Render(request))
            },
        );
        let admitted = match admitted {
            Ok(value) => value,
            Err(error) => {
                // A queue refusal admits nothing and retains the buffer for retry.
                // A missing/malformed policy, however, cannot authorize another
                // request; close output rather than guessing a budget.
                if self
                    .vault
                    .hosted_tts_limits(self.binding.provider.target(), self.binding.owner)
                    .is_err()
                {
                    self.revoke(generation);
                }
                return Err(error);
            }
        };
        if admitted.is_none() {
            self.revoke(generation);
            return Err(invalid("voice target withdrawn, evicted or stale"));
        }
        self.pending.push_back(PendingResponse {
            submission: self.next_submission,
            next_chunk: 0,
        });
        self.next_submission = next;
        self.buffer.clear();
        Ok(())
    }

    /// Receive one ALIGNED raw PCM16LE fragment from the host. HTTP chunk
    /// boundaries are arbitrary: the host must carry a trailing half-sample
    /// into the next read. Neither a WAV header nor MP3 is accepted here.
    pub fn receive_pcm(
        &mut self,
        generation: GenerationEpoch,
        submission: u64,
        chunk: u64,
        bytes: &[u8],
    ) -> Result<PcmFrame> {
        if self.generation != Some(generation) || !matches!(self.phase, Phase::Open | Phase::Ended)
        {
            return Err(invalid("stale or cancelled response"));
        }
        let limits = self.ensure_live(generation)?;
        let Some(front) = self.pending.front() else {
            return Err(invalid("unsolicited response"));
        };
        if front.submission != submission || front.next_chunk != chunk {
            return Err(invalid("stale or out-of-order response"));
        }
        if bytes.is_empty()
            || bytes.len() > limits.max_pcm_fragment_bytes
            || !bytes.len().is_multiple_of(2)
        {
            return Err(invalid("invalid raw PCM16 fragment"));
        }
        let next = front
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| invalid("PCM sequence exhausted"))?;
        let samples = bytes
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        self.pending
            .front_mut()
            .expect("validated pending response")
            .next_chunk = next;
        Ok(PcmFrame {
            generation,
            sample_rate: PCM_RATE,
            samples,
        })
    }

    /// Receive one whole sentence's audio from the media worker
    /// ([`VoiceMediaOutput::Pcm`](super::media::VoiceMediaOutput::Pcm)) for
    /// `submission`, at the rate its answer said. It completes that render.
    pub fn receive_frame(&mut self, submission: u64, frame: PcmFrame) -> Result<PcmFrame> {
        let generation = frame.generation;
        if self.generation != Some(generation) || !matches!(self.phase, Phase::Open | Phase::Ended)
        {
            return Err(invalid("stale or cancelled response"));
        }
        self.ensure_live(generation)?;
        if self
            .pending
            .front()
            .is_none_or(|front| front.submission != submission || front.next_chunk != 0)
        {
            return Err(invalid("stale or out-of-order response"));
        }
        if frame.samples.is_empty() {
            return Err(invalid("invalid PCM frame"));
        }
        self.pending.pop_front();
        Ok(frame)
    }

    pub fn finish_response(&mut self, generation: GenerationEpoch, submission: u64) -> Result<()> {
        if self.generation != Some(generation) || !matches!(self.phase, Phase::Open | Phase::Ended)
        {
            return Err(invalid("stale or cancelled completion"));
        }
        self.ensure_live(generation)?;
        if self.pending.front().map(|response| response.submission) != Some(submission) {
            return Err(invalid("unmatched response completion"));
        }
        self.pending.pop_front();
        Ok(())
    }

    /// Provider output is not playout authority; use at enqueue AND playback.
    pub fn filter_pcm(&self, session: &VoiceCascadeSession, frame: PcmFrame) -> Option<PcmFrame> {
        session.filter_pcm(frame)
    }
}

impl<T: HostedTransport> TtsSeamClient for HostedTtsAdapter<'_, T> {
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
            self.generation = Some(generation);
            self.ensure_live(generation)?;
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
                self.pending.clear();
                self.transport
                    .try_submit(HostedWork::Cancel { generation })?;
                self.phase = Phase::Cancelled;
            }
            return Ok(());
        }
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        if matches!(self.phase, Phase::Open | Phase::Ended) {
            self.ensure_live(generation)?;
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
                let limits = self.ensure_live(generation)?;
                if text.is_empty()
                    || text.len() > limits.max_text_bytes.saturating_sub(self.buffer.len())
                {
                    return Err(invalid("policy text limit exceeded"));
                }
                self.buffer.push_str(&text);
            }
            TtsCommand::Flush { .. } => self.flush(generation)?,
            TtsCommand::End { .. } => {
                self.flush(generation)?;
                self.phase = Phase::Ended;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
