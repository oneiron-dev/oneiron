//! Moved from `crates/oneiron/src/policy_model/request.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::policy_model::request::PolicyClassifySubject;
use serde::Deserialize;
use serde::Serialize;

/// How hard the safeguard model should think before answering.
///
/// Reasoning safeguard models expose this as a knob rather than inferring it,
/// and the right setting depends on how subtle the substrate owner's policy is
/// — which is their call, not the engine's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasoningEffort {
    Low,
    #[default]
    Medium,
    High,
}

impl PolicyReasoningEffort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Generation parameters for a safeguard-model call.
///
/// `max_output_tokens` defaults to NO CAP on purpose. A reasoning safeguard
/// model spends output tokens on its reasoning before it answers, so a small
/// ceiling truncates the answer into something unreadable and the plane
/// degrades for a reason that was never about the content. A host that needs a
/// ceiling sets a generous one here.
///
/// These are per-config, and a host that drives more than one safeguard binding
/// gives each binding its own [`PolicyModelConfig`] — the parameters travel
/// with the binding they were tuned for.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyGenerationParams {
    pub reasoning_effort: PolicyReasoningEffort,
    pub temperature: f32,
    pub max_output_tokens: Option<u32>,
}

impl Default for PolicyGenerationParams {
    fn default() -> Self {
        Self {
            reasoning_effort: PolicyReasoningEffort::Medium,
            temperature: 0.0,
            max_output_tokens: None,
        }
    }
}
