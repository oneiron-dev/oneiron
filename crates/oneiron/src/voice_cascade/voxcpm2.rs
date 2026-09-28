//! VoxCPM2's warm, host-owned rendering seam. The audio worker lives outside
//! the cascade lock; this adapter only admits bounded work and checks its replies.
//! A host must supply a queue connected to an already-loaded GPU process. Neither
//! queue admission nor a host readiness claim alone proves a GPU is deployed.

pub use crate::gate::voice_serving::VoiceServingLimits;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};

use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    voice_identity::ref_bank::{VoiceRefFence, VoiceRegisterClip},
};

const TARGET: &str = "voxcpm2";
pub const MODEL: &str = "VoxCPM2";

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("VoxCPM2: {message}"))
}

/// Host-reported pins from a *loaded*, ready worker, not a request to cold-start.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WarmTarget {
    pub limits: VoiceServingLimits,
    pub model: String,
    pub checkpoint: String,
    pub boot_id: String,
    pub sample_rate: u32,
}

impl WarmTarget {
    fn validate(&self) -> Result<()> {
        if !self.limits.valid()
            || self.model != MODEL
            || self.checkpoint.trim().is_empty()
            || self.checkpoint.len() > 512
            || self.boot_id.trim().is_empty()
            || self.boot_id.len() > 512
            || !(8_000..=192_000).contains(&self.sample_rate)
        {
            return Err(invalid("worker is not a pinned, ready VoxCPM2 target"));
        }
        Ok(())
    }
}

/// The identity used for both queue admission and callback validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderTarget {
    pub voice_id: String,
    pub register: String,
    pub fence: VoiceRefFence,
    pub limits: VoiceServingLimits,
    pub warm: WarmTarget,
}

impl RenderTarget {
    fn with_current<T>(
        &self,
        vault: &Vault,
        operation: impl FnOnce(&VoiceRegisterClip) -> Result<T>,
    ) -> Result<T> {
        vault.with_fenced_voice_clone(&self.voice_id, TARGET, &self.fence, |clone| {
            let clip = clone
                .clips
                .iter()
                .find(|clip| clip.register == self.register)
                .ok_or_else(|| invalid("register is not banked"))?;
            operation(clip)
        })
    }

    /// Hosts must recheck at playback, not only on initial PCM admission.
    #[must_use]
    pub fn is_current_in(&self, vault: &Vault) -> bool {
        vault
            .voice_ref_fence_current_now(&self.voice_id, TARGET, &self.fence)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoxCpm2Operation {
    Start { target: Box<RenderTarget> },
    Render { text: String },
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoxCpm2Work {
    pub generation: GenerationEpoch,
    pub sequence: u64,
    pub operation: VoxCpm2Operation,
}

/// Host queue calls must return immediately, admit one work item or nothing,
/// and preserve FIFO. Model loading and HTTP/GPU work belong on its worker.
/// A readiness check must inspect a running process, not an intended deploy.
pub trait VoxCpm2Queue {
    fn warm_target(&self) -> Result<WarmTarget>;
    fn try_submit(&mut self, work: VoxCpm2Work) -> Result<()>;
}

/// The worker's actual PCM16LE result. The host must not invent the target
/// metadata; it must compare the response's pins and selected source with this.
pub struct VoxCpm2Audio<'a> {
    pub generation: GenerationEpoch,
    pub submission: u64,
    pub chunk_index: u64,
    pub target: RenderTarget,
    pub channels: u16,
    pub bytes: &'a [u8],
}

#[must_use = "filter and forward PCM through the active cascade, or discard it"]
pub struct VoxCpm2Pcm {
    frame: PcmFrame,
    vault: Arc<Vault>,
    pub target: RenderTarget,
}

impl VoxCpm2Pcm {
    #[must_use]
    pub fn filter_pcm(self, session: &VoiceCascadeSession) -> Option<(PcmFrame, RenderTarget)> {
        if !self.target.is_current_in(&self.vault) {
            return None;
        }
        session
            .filter_pcm(self.frame)
            .map(|frame| (frame, self.target))
    }
}

/// One generation, one banked voice identity, one warm target. The identity's
/// source refs are fenced at Start; a withdrawal or ref change stops the render.
pub struct VoxCpm2Adapter<Q> {
    vault: Arc<Vault>,
    limits: VoiceServingLimits,
    voice_id: String,
    register: String,
    queue: Q,
    generation: Option<GenerationEpoch>,
    target: Option<RenderTarget>,
    sequence: u64,
    chunk_index: u64,
    text_bytes: usize,
    buffer: String,
    pending: VecDeque<u64>,
    ended: bool,
    cancelled: bool,
}

impl<Q: VoxCpm2Queue> VoxCpm2Adapter<Q> {
    pub fn new(vault: Arc<Vault>, voice_id: &str, register: &str, queue: Q) -> Result<Self> {
        Self::new_for_holder(vault, voice_id, register, None, queue)
    }

    /// `holder` must come from the authenticated host identity, not speech.
    pub fn new_for_holder(
        vault: Arc<Vault>,
        voice_id: &str,
        register: &str,
        holder: Option<EntityId>,
        queue: Q,
    ) -> Result<Self> {
        let limits = vault.voice_serving_limits(holder)?;
        if voice_id.trim().is_empty() || register.trim().is_empty() || register.len() > 128 {
            return Err(invalid("invalid reference selection"));
        }
        Ok(Self {
            vault,
            limits,
            voice_id: voice_id.into(),
            register: register.into(),
            queue,
            generation: None,
            target: None,
            sequence: 0,
            chunk_index: 0,
            text_bytes: 0,
            buffer: String::new(),
            pending: VecDeque::new(),
            ended: false,
            cancelled: false,
        })
    }

    #[must_use]
    pub fn target(&self) -> Option<&RenderTarget> {
        self.target.as_ref()
    }

    /// Drain host-owned render events outside the cascade lock. The queue
    /// retains no vault authority; only `handle_pcm` can match its result.
    #[must_use]
    pub fn queue(&self) -> &Q {
        &self.queue
    }

    fn send(&mut self, generation: GenerationEpoch, operation: VoxCpm2Operation) -> Result<u64> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        self.queue.try_submit(VoxCpm2Work {
            generation,
            sequence: self.sequence,
            operation,
        })?;
        let admitted = self.sequence;
        self.sequence = next;
        Ok(admitted)
    }

    fn boundary(&mut self, generation: GenerationEpoch, end: bool) -> Result<()> {
        if !self.buffer.is_empty() {
            // Never wait on the ref guard here: GPU work can hold a read lock
            // while a withdrawal waits to write. The worker checks the exact
            // revision at dispatch; returned PCM is checked before playback.
            if self.pending.len() >= self.limits.max_queued_renders as usize {
                return Err(invalid("responses must drain"));
            }
            let submission = self.send(
                generation,
                VoxCpm2Operation::Render {
                    text: self.buffer.clone(),
                },
            )?;
            self.pending.push_back(submission);
            self.buffer.clear();
        }
        if end {
            self.ended = true;
        }
        Ok(())
    }

    /// Only a response to an admitted render may be emitted. No WAV slicing or
    /// unnegotiated chunking; one complete PCM result per render submission.
    pub fn handle_pcm(&mut self, audio: VoxCpm2Audio<'_>) -> Result<VoxCpm2Pcm> {
        if self.generation != Some(audio.generation)
            || self.cancelled
            || self.pending.front() != Some(&audio.submission)
            || audio.chunk_index != self.chunk_index
            || self.target.as_ref() != Some(&audio.target)
            || audio.channels != 1
            || audio.bytes.is_empty()
            || audio.bytes.len() as u64 > self.limits.max_pcm_bytes
            || !audio.bytes.len().is_multiple_of(2)
        {
            return Err(invalid("unmatched target, submission or PCM format"));
        }
        if !audio.target.is_current_in(&self.vault) {
            self.cancelled = true;
            self.pending.clear();
            return Err(invalid("owner voice reference withdrawn or replaced"));
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
        self.pending.pop_front();
        Ok(VoxCpm2Pcm {
            vault: Arc::clone(&self.vault),
            frame: PcmFrame {
                generation: audio.generation,
                sample_rate: audio.target.warm.sample_rate,
                samples,
            },
            target: audio.target,
        })
    }
}

impl<Q: VoxCpm2Queue> TtsSeamClient for VoxCpm2Adapter<Q> {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if let TtsCommand::Start { .. } = command {
            if self.generation.is_some() || self.cancelled {
                return Err(invalid("single-generation adapter"));
            }
            let warm = self.queue.warm_target()?;
            warm.validate()?;
            if !self.limits.within(warm.limits) {
                return Err(invalid("worker serving limits narrower than vault policy"));
            }
            // Source refs only: generated refs never stand in for the identity.
            let (cloned, fence) =
                self.vault
                    .prepare_fenced_voice_clone(&self.voice_id, TARGET, false)?;
            let reference = cloned
                .clips
                .into_iter()
                .find(|clip| clip.register == self.register)
                .ok_or_else(|| invalid("register is not banked"))?;
            if reference.media_type != "audio/wav"
                || reference.audio.len() < 12
                || !reference.audio.starts_with(b"RIFF")
                || &reference.audio[8..12] != b"WAVE"
                || reference.transcript.trim().is_empty()
                || reference.audio.len() as u64 > self.limits.max_ref_bytes
            {
                return Err(invalid("VoxCPM2 requires a WAV reference and transcript"));
            }
            let target = RenderTarget {
                voice_id: cloned.voice_id,
                register: self.register.clone(),
                fence,
                limits: self.limits,
                warm,
            };
            self.send(
                generation,
                VoxCpm2Operation::Start {
                    target: Box::new(target.clone()),
                },
            )?;
            self.target = Some(target);
            self.generation = Some(generation);
            return Ok(());
        }
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        if let TtsCommand::Cancel { .. } = command {
            // Fail closed before queue admission. A failed cancel permits a retry only.
            self.cancelled = true;
            self.buffer.clear();
            self.pending.clear();
            self.send(generation, VoxCpm2Operation::Cancel)?;
            return Ok(());
        }
        if self.cancelled {
            return Err(invalid("output cancelled"));
        }
        if self.ended {
            return if matches!(command, TtsCommand::End { .. } | TtsCommand::Flush { .. }) {
                Ok(())
            } else {
                Err(invalid("input closed"))
            };
        }
        match command {
            TtsCommand::Text { text, .. } => {
                if text.trim().is_empty()
                    || text.len() as u64 > self.limits.max_text_bytes - self.text_bytes as u64
                {
                    return Err(invalid("empty or oversized text"));
                }
                self.text_bytes += text.len();
                self.buffer.push_str(&text);
            }
            TtsCommand::Flush { .. } => self.boundary(generation, false)?,
            TtsCommand::End { .. } => self.boundary(generation, true)?,
            _ => unreachable!("Start and Cancel handled above"),
        }
        Ok(())
    }
}

impl Vault {
    /// Resolve the live trusted manifest, including vault and authenticated
    /// holder narrowing. Missing or malformed policy refuses serving.
    pub fn voice_serving_limits(&self, holder: Option<EntityId>) -> Result<VoiceServingLimits> {
        let txn = self.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&self.store, &txn)?.voice_serving_limits(holder)
    }
}

pub mod http;

#[cfg(test)]
mod tests;
