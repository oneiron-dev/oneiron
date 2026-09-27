//! Hosted TTS request adapters. A vault ref pack is the identity; provider voice IDs
//! are disposable, pre-provisioned render targets. No provisioning, credentials,
//! network I/O, PCM buffering or provider selection runs under the cascade lock.
//! The host owns HTTP, response streaming and cancellation. It must frame raw
//! PCM16 across arbitrary HTTP chunk boundaries and recheck the epoch at playback.

use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};

const MAX_TEXT_BYTES: usize = 8 * 1024;
const MAX_PCM_BYTES: usize = 2 * 1024 * 1024;
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

/// Provisioning happens from `Vault::clone_voice_refs_into` OUTSIDE this adapter.
/// A voice ID is a provider-scoped, disposable locator, never the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedBinding {
    pub provider: HostedProvider,
    pub source_pack: String,
    pub owner: EntityId,
    pub voice_id: String,
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

/// Bind a banked identity to ONE pre-provisioned voice on ONE hosted target.
/// `vault` remains the authority: an unknown or withdrawn pack cannot bind.
/// This adapter does not retain the cloned reference audio.
pub struct HostedTtsAdapter<T> {
    transport: T,
    binding: HostedBinding,
    generation: Option<GenerationEpoch>,
    phase: Phase,
    buffer: String,
    text_bytes: usize,
    next_submission: u64,
    in_flight: Option<u64>,
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

impl<T: HostedTransport> HostedTtsAdapter<T> {
    pub fn bind(
        vault: &Vault,
        pack_id: &str,
        provider: HostedProvider,
        voice_id: &str,
        transport: T,
    ) -> Result<Self> {
        // Restrict path interpolation and do not accept URLs, whitespace or credentials.
        if voice_id.is_empty()
            || voice_id.len() > 128
            || !voice_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("invalid pre-provisioned voice id"));
        }
        let target = vault.clone_voice_refs_into(pack_id, provider.target())?;
        Ok(Self {
            transport,
            binding: HostedBinding {
                provider,
                source_pack: target.source_pack,
                owner: target.owner,
                voice_id: voice_id.into(),
            },
            generation: None,
            phase: Phase::Fresh,
            buffer: String::new(),
            text_bytes: 0,
            next_submission: 0,
            in_flight: None,
            next_chunk: 0,
        })
    }

    pub fn binding(&self) -> &HostedBinding {
        &self.binding
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn request(&self, generation: GenerationEpoch, submission: u64) -> HostedRender {
        let (url, api_version, body) = match self.binding.provider {
            HostedProvider::Cartesia => (
                "https://api.cartesia.ai/tts/bytes".into(),
                Some("2026-08-14"),
                serde_json::json!({"model_id":"sonic-3.5","transcript":self.buffer,
                    "voice":{"id":self.binding.voice_id},
                    "output_format":{"container":"raw","encoding":"pcm_s16le","sample_rate":PCM_RATE}}),
            ),
            HostedProvider::ElevenLabsFlash => (
                format!(
                    "https://api.elevenlabs.io/v1/text-to-speech/{}/stream?output_format=pcm_24000",
                    self.binding.voice_id
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

    fn flush(&mut self, generation: GenerationEpoch) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.in_flight.is_some() {
            return Err(invalid("response still in flight"));
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let request = self.request(generation, self.next_submission);
        self.transport.try_submit(HostedWork::Render(request))?;
        self.in_flight = Some(self.next_submission);
        self.next_submission = next;
        self.next_chunk = 0;
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
        if self.generation != Some(generation)
            || !matches!(self.phase, Phase::Open | Phase::Ended)
            || self.in_flight != Some(submission)
            || self.next_chunk != chunk
        {
            return Err(invalid("stale or out-of-order response"));
        }
        if bytes.is_empty() || bytes.len() > MAX_PCM_BYTES || !bytes.len().is_multiple_of(2) {
            return Err(invalid("invalid raw PCM16 fragment"));
        }
        let next = self
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| invalid("PCM sequence exhausted"))?;
        let samples = bytes
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        self.next_chunk = next;
        Ok(PcmFrame {
            generation,
            sample_rate: PCM_RATE,
            samples,
        })
    }

    pub fn finish_response(&mut self, generation: GenerationEpoch, submission: u64) -> Result<()> {
        if self.generation != Some(generation)
            || !matches!(self.phase, Phase::Open | Phase::Ended)
            || self.in_flight != Some(submission)
        {
            return Err(invalid("unmatched response completion"));
        }
        self.in_flight = None;
        Ok(())
    }

    /// Provider output is not playout authority; use at enqueue AND playback.
    pub fn filter_pcm(&self, session: &VoiceCascadeSession, frame: PcmFrame) -> Option<PcmFrame> {
        session.filter_pcm(frame)
    }
}

impl<T: HostedTransport> TtsSeamClient for HostedTtsAdapter<T> {
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
                self.in_flight = None;
                self.transport
                    .try_submit(HostedWork::Cancel { generation })?;
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
                if text.is_empty() || text.len() > MAX_TEXT_BYTES - self.text_bytes {
                    return Err(invalid("text limit exceeded"));
                }
                self.text_bytes += text.len();
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
