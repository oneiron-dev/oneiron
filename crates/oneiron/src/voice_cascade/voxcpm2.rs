//! VoxCPM2's warm, host-owned rendering seam. The audio worker lives outside
//! the cascade lock; this adapter only admits work and checks its replies.
//! Nothing is refused for its size or for room (Rule 5): text past the
//! serving policy's `max_text_bytes` goes as several renders, in order,
//! renders past its `max_queued_renders` wait in the adapter until earlier
//! audio drains, and a long reference clip is sent whole, asking past its
//! `[limits]` row.
//! A host must supply a queue connected to an already-loaded GPU process. Neither
//! queue admission nor a host readiness claim alone proves a GPU is deployed.

pub use crate::gate::voice_serving::{VoiceServingLimits, VoiceServingPolicyReceipt};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};

use super::{GenerationEpoch, PcmFrame, TtsCommand, TtsSeamClient, VoiceCascadeSession, speakable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    limit_ask::EngineLimit,
    llm::{
        CacheIdentity, InferenceCallReceipt, ModelId, ModelLocality, WorkerBuildEvidence,
        WorkerDescriptor, WorkerKind,
    },
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
    /// Whether the worker reported a pinned, ready VoxCPM2 with a valid
    /// serving policy.
    pub fn validate(&self) -> Result<()> {
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

    /// The worker this target names, as far as `/ready` proves it (FIX 8314,
    /// INFERENCE R1): a VoxCPM2 worker. Its checkpoint is a configured
    /// revision and its boot id a process's, neither a digest of what it
    /// loaded or runs, so the identity names nothing and the build is
    /// unknown. Not readiness: a render matching a pinned build is.
    #[must_use]
    pub fn worker(&self) -> WorkerDescriptor {
        WorkerDescriptor {
            kind: WorkerKind::VoxCpm2,
            identity: CacheIdentity::default(),
            build_evidence: WorkerBuildEvidence::Unknown,
        }
    }

    /// One render's receipt, for a call admitted for `model`: the worker,
    /// and no count, wait or time, none of which the worker reports.
    #[must_use]
    pub fn render_receipt(&self, model: &ModelId) -> InferenceCallReceipt {
        InferenceCallReceipt::unmeasured(Some(model.clone()), self.worker())
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
    /// The submission's complete result, in memory or spilled (C058).
    pub body: &'a Arc<VoxCpm2PcmBody>,
}

/// One admitted result, played out a window at a time: each window is a
/// local read of the same submission's result, never another worker render.
#[must_use = "filter and forward PCM through the active cascade, or discard it"]
pub struct VoxCpm2Pcm {
    body: Arc<VoxCpm2PcmBody>,
    /// The next window's offset in the result.
    offset: u64,
    generation: GenerationEpoch,
    vault: Arc<Vault>,
    pub target: RenderTarget,
}

impl VoxCpm2Pcm {
    /// The next playback window of the result, through the active cascade.
    /// The withdrawal fence is rechecked for every window: a withdrawn or
    /// replaced reference, or a cascade that no longer takes this
    /// generation, ends the playback (`None` from then on), as the end of
    /// the result does.
    ///
    /// # Errors
    ///
    /// A spilled result's read error.
    pub fn next_window(
        &mut self,
        session: &VoiceCascadeSession,
    ) -> Result<Option<(PcmFrame, RenderTarget)>> {
        if self.offset >= self.body.len() {
            return Ok(None);
        }
        if !self.target.is_current_in(&self.vault) {
            self.offset = self.body.len();
            return Ok(None);
        }
        let bytes = self.body.read(self.offset, PCM_WINDOW_BYTES)?;
        let frame = PcmFrame {
            generation: self.generation,
            sample_rate: self.target.warm.sample_rate,
            samples: bytes
                .chunks_exact(2)
                .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
                .collect(),
        };
        let Some(frame) = session.filter_pcm(frame) else {
            self.offset = self.body.len();
            return Ok(None);
        };
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        Ok(Some((frame, self.target.clone())))
    }
}

/// One generation, one banked voice identity, one warm target. The identity's
/// source refs are fenced at Start, under the render consent that reaches the
/// worker; a withdrawal, a new render decision or a ref change stops the render.
pub struct VoxCpm2Adapter<Q> {
    vault: Arc<Vault>,
    /// The serving policy this adapter resolved, kept whole: its limits, and
    /// whether the shipped defaults stood in for an absent row (FIX 8772).
    policy: VoiceServingPolicyReceipt,
    voice_id: String,
    register: String,
    /// Where the host's worker runs.
    locality: ModelLocality,
    queue: Q,
    generation: Option<GenerationEpoch>,
    target: Option<RenderTarget>,
    sequence: u64,
    chunk_index: u64,
    buffer: String,
    /// Renders waiting, in order, for fewer than `max_queued_renders` to
    /// await their audio.
    held: VecDeque<String>,
    pending: VecDeque<u64>,
    ended: bool,
    cancelled: bool,
}

impl<Q> VoxCpm2Adapter<Q> {
    /// The serving policy this adapter resolved, and whether the shipped
    /// defaults stood in for an absent row (FIX 8772).
    #[must_use]
    pub fn serving_policy(&self) -> VoiceServingPolicyReceipt {
        self.policy
    }
}

impl<Q: VoxCpm2Queue> VoxCpm2Adapter<Q> {
    /// `locality` is where the host's worker runs; the reference clip is the
    /// person's raw voice, so a third party's worker refuses.
    pub fn new(
        vault: Arc<Vault>,
        voice_id: &str,
        register: &str,
        locality: ModelLocality,
        queue: Q,
    ) -> Result<Self> {
        Self::new_for_holder(vault, voice_id, register, None, locality, queue)
    }

    /// `holder` must come from the authenticated host identity, not speech.
    pub fn new_for_holder(
        vault: Arc<Vault>,
        voice_id: &str,
        register: &str,
        holder: Option<EntityId>,
        locality: ModelLocality,
        queue: Q,
    ) -> Result<Self> {
        if locality == ModelLocality::ThirdParty {
            return Err(invalid("a voice reference never goes to a third party"));
        }
        let policy = vault.voice_serving_policy(holder)?;
        if voice_id.trim().is_empty() || register.trim().is_empty() || register.len() > 128 {
            return Err(invalid("invalid reference selection"));
        }
        Ok(Self {
            vault,
            policy,
            voice_id: voice_id.into(),
            register: register.into(),
            locality,
            queue,
            generation: None,
            target: None,
            sequence: 0,
            chunk_index: 0,
            buffer: String::new(),
            held: VecDeque::new(),
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
            let max = usize::try_from(self.policy.limits.max_text_bytes).unwrap_or(usize::MAX);
            let pieces = speakable::pieces(&self.buffer, max);
            self.held.extend(pieces.into_iter().map(str::to_owned));
            self.buffer.clear();
        }
        if end {
            self.ended = true;
        }
        self.release(generation)
    }

    /// Sends held renders while fewer than `max_queued_renders` await their
    /// audio; the rest wait for it to drain. A refused send keeps its render
    /// held for the next boundary or response.
    fn release(&mut self, generation: GenerationEpoch) -> Result<()> {
        let window = usize::try_from(self.policy.limits.max_queued_renders).unwrap_or(usize::MAX);
        // Never wait on the ref guard here: GPU work can hold a read lock
        // while a withdrawal waits to write. The worker checks the exact
        // revision at dispatch; returned PCM is checked before playback.
        while self.pending.len() < window
            && let Some(text) = self.held.front()
        {
            let text = text.clone();
            let submission = self.send(generation, VoxCpm2Operation::Render { text })?;
            self.held.pop_front();
            self.pending.push_back(submission);
        }
        Ok(())
    }

    /// Only a response to an admitted render may be emitted. No WAV slicing or
    /// unnegotiated chunking; one complete PCM result per render submission,
    /// which its [`VoxCpm2Pcm`] plays out in local windows.
    pub fn handle_pcm(&mut self, audio: VoxCpm2Audio<'_>) -> Result<VoxCpm2Pcm> {
        if self.generation != Some(audio.generation)
            || self.cancelled
            || self.pending.front() != Some(&audio.submission)
            || audio.chunk_index != self.chunk_index
            || self.target.as_ref() != Some(&audio.target)
            || audio.channels != 1
            || audio.body.is_empty()
            || !audio.body.len().is_multiple_of(2)
        {
            return Err(invalid("unmatched target, submission or PCM format"));
        }
        if !audio.target.is_current_in(&self.vault) {
            self.cancelled = true;
            self.held.clear();
            self.pending.clear();
            return Err(invalid("owner voice reference withdrawn or replaced"));
        }
        let next = self
            .chunk_index
            .checked_add(1)
            .ok_or_else(|| invalid("PCM sequence exhausted"))?;
        self.chunk_index = next;
        self.pending.pop_front();
        // A held render takes the room this one left. A refused send stays
        // held; the queue reports its own failure on the next receive.
        let _ = self.release(audio.generation);
        Ok(VoxCpm2Pcm {
            body: Arc::clone(audio.body),
            offset: 0,
            generation: audio.generation,
            vault: Arc::clone(&self.vault),
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
            if !self.policy.limits.within(warm.limits) {
                return Err(invalid("worker serving limits narrower than vault policy"));
            }
            // Source refs only: generated refs never stand in for the identity.
            let (cloned, fence) = self.vault.prepare_fenced_voice_clone(
                &self.voice_id,
                TARGET,
                false,
                self.locality,
            )?;
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
            {
                return Err(invalid("VoxCPM2 requires a WAV reference and transcript"));
            }
            // Sent whole; past its `[limits]` row it asks whether all is well.
            self.vault.measure_limit(
                EngineLimit::VoiceReferenceBytes,
                u64::try_from(reference.audio.len()).unwrap_or(u64::MAX),
            );
            let target = RenderTarget {
                voice_id: cloned.voice_id,
                register: self.register.clone(),
                fence,
                limits: self.policy.limits,
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
            self.held.clear();
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
                // Long text is split into renders at the boundary, never refused.
                if text.trim().is_empty() {
                    return Err(invalid("empty text"));
                }
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
    /// Resolve the live trusted manifest's voice serving policy, including
    /// vault and authenticated holder narrowing, with whether the shipped
    /// defaults stood in for an absent row. Unreadable, malformed or
    /// untrusted policy refuses serving (FIX 8772).
    pub fn voice_serving_policy(
        &self,
        holder: Option<EntityId>,
    ) -> Result<VoiceServingPolicyReceipt> {
        let txn = self.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&self.store, &txn)?.voice_serving_policy(holder)
    }

    /// The limits of [`Self::voice_serving_policy`], for a caller that
    /// keeps the policy's receipt elsewhere.
    pub fn voice_serving_limits(&self, holder: Option<EntityId>) -> Result<VoiceServingLimits> {
        Ok(self.voice_serving_policy(holder)?.limits)
    }
}

pub mod http;
mod pcm;
use pcm::PCM_WINDOW_BYTES;
pub use pcm::VoxCpm2PcmBody;

#[cfg(test)]
mod tests;
