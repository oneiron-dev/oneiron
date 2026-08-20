//! What the caller asks about, and how the classifier is configured.

use serde::{Deserialize, Serialize};

use crate::llm::SafeguardModelBinding;
use crate::store::GateSystemNoticeAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClassifySubject {
    OutboundContent,
    Action,
}

impl PolicyClassifySubject {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundContent => "outbound_content",
            Self::Action => "action",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyRequest {
    pub subject: PolicyClassifySubject,
    pub content: String,
    pub world_ref: Option<String>,
    pub caller_ref: Option<String>,
}

impl PolicyClassifyRequest {
    #[must_use]
    pub fn outbound_content(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::OutboundContent,
            content: content.into(),
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn action(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::Action,
            content: content.into(),
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn with_world_ref(mut self, world_ref: impl Into<String>) -> Self {
        self.world_ref = Some(world_ref.into());
        self
    }

    #[must_use]
    pub fn with_caller_ref(mut self, caller_ref: impl Into<String>) -> Self {
        self.caller_ref = Some(caller_ref.into());
        self
    }
}

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

/// How much of the relayed content the safeguard model sees.
///
/// `non_exhaustive`: a new mode is how this grows, and a downstream exhaustive
/// match would turn that into a breaking change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayClassifierMode {
    /// The default. The model classifies 100% of relayed content; pattern hits
    /// annotate the pass (and a `Decide` hit still short-circuits it), but no
    /// pattern is required for the model to look.
    #[default]
    ClassifyAll,
    /// Patterns gate the model. A `Decide` hit is the verdict, an `Escalate`
    /// hit buys a model call, and content that matched only `Log` rules — or
    /// nothing at all — is allowed with ZERO model calls and its own receipt
    /// reason.
    PatternGated,
}

impl RelayClassifierMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClassifyAll => "classify_all",
            Self::PatternGated => "pattern_gated",
        }
    }
}

/// Everything about a classify pass that is the HOST's to choose. None of it
/// carries policy content: the patterns and the policy documents live on their
/// own planes, where their authority comes from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicyModelConfig {
    pub safeguard_binding: SafeguardModelBinding,
    /// Affordance the host attaches to owner-plane notices so the owner can
    /// jump straight to the setting that fired. `None` by default: the engine
    /// knows no product routes, so a host that wants the offer supplies both
    /// its label and its target.
    pub owner_setting_change_offer: Option<GateSystemNoticeAction>,
    pub generation: PolicyGenerationParams,
    pub relay_classifier_mode: RelayClassifierMode,
}
