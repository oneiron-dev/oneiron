//! Moved from `crates/oneiron/src/voice_cascade/voxcpm2.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::gate::voice_serving::VoiceServingLimits;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_model::llm::CacheEpoch;
use oneiron_model::llm::CacheIdentity;
use oneiron_model::llm::InferenceCallReceipt;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::WorkerBuildEvidence;
use oneiron_model::llm::WorkerDescriptor;
use oneiron_model::llm::WorkerKind;
use serde::Deserialize;
use serde::Serialize;

pub const MODEL: &str = "VoxCPM2";

pub fn invalid(message: &str) -> Error {
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

    /// A worker's `/ready` answer: the `transcript_frame` capability said
    /// beside the warm target, then the strict target itself. Each caller
    /// keeps its own validation and error mapping.
    pub fn from_ready(mut ready: serde_json::Value) -> serde_json::Result<(Self, bool)> {
        let takes_frame = ready
            .as_object_mut()
            .and_then(|fields| fields.remove("transcript_frame"))
            == Some(serde_json::Value::Bool(true));
        let warm = serde_json::from_value(ready)?;
        Ok((warm, takes_frame))
    }

    /// The worker this target names, as far as `/ready` proves it (FIX 8314,
    /// INFERENCE R1): a VoxCPM2 worker, and the incarnation that answered.
    /// Its boot id, minted once per process as 32 hex digits, is the
    /// identity's `backend_epoch` (FIX 8898); a boot id of another shape
    /// names no epoch. Its checkpoint is a configured revision, not a digest
    /// of what it loaded or runs, so no other identity field is named and
    /// the build is unknown. Not readiness: a render matching a pinned build
    /// is.
    #[must_use]
    pub fn worker(&self) -> WorkerDescriptor {
        WorkerDescriptor {
            kind: WorkerKind::VoxCpm2,
            identity: CacheIdentity {
                backend_epoch: CacheEpoch::new(self.boot_id.clone()).ok(),
                ..CacheIdentity::default()
            },
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
