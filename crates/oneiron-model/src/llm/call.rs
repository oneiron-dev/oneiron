//! Per-call description: envelope, pin admission, roles, tier precedence, response format, and
//! locality. `RoleModelDefaults` stays in `oneiron`: it resolves routing hints from a vault.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::ModelId;
use super::model_id::validated_static_model_id;
use super::protocol::LlmRequest;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallEnvelope {
    #[serde(default)]
    pub scope: super::scope::Scope,
    pub purpose: CallPurpose,
    pub class: CallClass,
    pub tier: TierPrecedence,
    pub response_format: ResponseFormat,
    pub locality: ModelLocality,
    /// Set only at seat birth; adapters make this pin authoritative over raw options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_effort: Option<super::ReasoningEffort>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallPurpose {
    Extraction,
    Consolidation,
    AnswerGen,
    AutoCheck,
    ToolRouting,
    Voice,
    Eval,
    Other { name: String },
}

/// Opt-in per-call model pin (ONE-1344): an explicit allow-list of fully
/// revisioned model ids plus the background-tier switch. There is NO default
/// policy, no environment lookup, and no catalog discovery — a caller either
/// supplies a config or runs unpinned. An empty `allowed` set is valid and
/// admits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedModelConfig {
    pub allowed: std::collections::BTreeSet<ModelId>,
    pub background_tier_enabled: bool,
}

/// Typed refusal from [`PinnedModelConfig::admit`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedConfigViolation {
    #[error("model is not present in the pinned model config: {model}")]
    ModelNotPinned { model: ModelId },
    #[error("background model tier is disabled for call purpose {purpose:?}")]
    BackgroundTierDisabled { purpose: CallPurpose },
}

impl PinnedModelConfig {
    /// Pre-admission check: membership FIRST, then background-tier
    /// classification. An unpinned model is always `ModelNotPinned`, even when
    /// its purpose would also fail the tier check.
    pub fn admit(&self, request: &LlmRequest) -> std::result::Result<(), PinnedConfigViolation> {
        if !self.allowed.contains(&request.model) {
            return Err(PinnedConfigViolation::ModelNotPinned {
                model: request.model.clone(),
            });
        }
        if !self.background_tier_enabled
            && matches!(
                &request.envelope.purpose,
                CallPurpose::Consolidation | CallPurpose::Extraction
            )
        {
            return Err(PinnedConfigViolation::BackgroundTierDisabled {
                purpose: request.envelope.purpose.clone(),
            });
        }
        Ok(())
    }
}

const ORCHESTRATOR_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1@2026-07-02";

const SUBAGENT_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1-mini@2026-07-02";

const SUMMARIZER_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1-nano@2026-07-02";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmRole {
    Orchestrator,
    Subagent,
    Summarizer,
}

impl LlmRole {
    #[must_use]
    pub const fn default_model_id_str(self) -> &'static str {
        match self {
            Self::Orchestrator => ORCHESTRATOR_DEFAULT_MODEL_ID,
            Self::Subagent => SUBAGENT_DEFAULT_MODEL_ID,
            Self::Summarizer => SUMMARIZER_DEFAULT_MODEL_ID,
        }
    }

    #[must_use]
    pub fn default_model_id(self) -> ModelId {
        validated_static_model_id(self.default_model_id_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallClass {
    Durable { fallback: DeterministicFallback },
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeterministicFallback {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelTierRef(pub String);

impl ModelTierRef {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolution inputs in precedence order:
/// seat override -> vault policy manifest -> purpose default -> global.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierPrecedence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_seat: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_policy: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_default: Option<ModelTierRef>,
    pub global_default: ModelTierRef,
}

impl TierPrecedence {
    #[must_use]
    pub fn resolved(&self) -> &ModelTierRef {
        self.per_seat
            .as_ref()
            .or(self.vault_policy.as_ref())
            .or(self.purpose_default.as_ref())
            .unwrap_or(&self.global_default)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ResponseFormat {
    Text,
    Json { schema: JsonValue },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLocality {
    OnDevice,
    OwnServer,
    ThirdParty,
}
