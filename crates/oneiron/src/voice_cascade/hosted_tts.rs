//! Hosted TTS request adapters. A vault voice identity is the identity; provider
//! voice IDs are disposable render targets read from its bank target records. No
//! provisioning, credentials, network I/O, PCM buffering or provider selection
//! runs under the cascade lock.
//! The host owns HTTP, response streaming and cancellation. It must frame raw
//! PCM16 across arbitrary HTTP chunk boundaries and recheck the epoch at playback.

use std::collections::VecDeque;

use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
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
}

/// A single complete HTTP request; host adds its own secret auth header and
/// streams the binary response. No audio/ref clips or credentials enter this DTO.
#[derive(Debug, Clone, PartialEq)]
pub struct HostedRender {
    pub generation: GenerationEpoch,
    pub submission: u64,
    pub provider: HostedProvider,
    pub url: String,
    pub api_version: Option<&'static str>,
    pub body: serde_json::Value,
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
/// Implementations never execute HTTP inside `try_submit`.
pub trait HostedTransport {
    fn try_submit(&mut self, work: HostedWork) -> Result<()>;
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
        let record = vault
            .voice_target_clone(voice_id, provider.target(), include_generated)?
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
        let (url, api_version, body) = match self.binding.provider {
            HostedProvider::Cartesia => (
                "https://api.cartesia.ai/tts/bytes".into(),
                Some("2026-08-14"),
                serde_json::json!({"model_id":"sonic-3.5","transcript":self.buffer,
                    "voice":{"id":self.binding.vendor_voice_id},
                    "output_format":{"container":"raw","encoding":"pcm_s16le","sample_rate":PCM_RATE}}),
            ),
            HostedProvider::ElevenLabsFlash => (
                format!(
                    "https://api.elevenlabs.io/v1/text-to-speech/{}/stream?output_format=pcm_24000",
                    self.binding.vendor_voice_id
                ),
                None,
                serde_json::json!({"model_id":"eleven_flash_v2_5","text":self.buffer}),
            ),
        };
        HostedRender {
            generation,
            submission,
            provider: self.binding.provider,
            url,
            api_version,
            body,
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
