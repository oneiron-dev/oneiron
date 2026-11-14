//! Moved from `crates/oneiron/src/store/model_step_submission.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::LlmRequest;
pub use oneiron_store::model_step_submission::*;
use serde::Deserialize;
use serde::Serialize;

/// Transport attempts per model request, including the first send. Retries
/// past the engine schedule wait its last interval (FIX 9930); the default is
/// the schedule's own four. Schema corrections remain the existing
/// one/native or three/shim paid calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepRetryPolicy {
    pub max_attempts: u8,
}

/// A caller-owned stable key freezes one exact request and its retry policy.
/// The envelope's CallClass declares the deterministic fallback, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepSubmit {
    pub step_key: String,
    pub request: LlmRequest,
    #[serde(default)]
    pub retry: ModelStepRetryPolicy,
}
