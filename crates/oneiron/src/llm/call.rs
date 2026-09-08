//! Per-call description: envelope, pin admission, role defaults, tier precedence, response format, and locality.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::ModelId;
use super::model_id::validated_static_model_id;
use super::protocol::LlmRequest;
use crate::Vault;
use crate::edit_distance::routing::{RoutingScopeKey, WeightHint, routing_weight_hint};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub purpose: CallPurpose,
    pub class: CallClass,
    pub tier: TierPrecedence,
    pub response_format: ResponseFormat,
    pub locality: ModelLocality,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleModelDefaults {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<LlmRole, ModelId>,
}

impl Default for RoleModelDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleModelDefaults {
    #[must_use]
    pub fn new() -> Self {
        Self {
            overrides: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_override(mut self, role: LlmRole, model: ModelId) -> Self {
        let _ = self.set_override(role, model);
        self
    }

    pub fn set_override(&mut self, role: LlmRole, model: ModelId) -> Option<ModelId> {
        self.overrides.insert(role, model)
    }

    #[must_use]
    pub fn override_for(&self, role: LlmRole) -> Option<&ModelId> {
        self.overrides.get(&role)
    }

    #[must_use]
    pub fn resolve(&self, role: LlmRole) -> ModelId {
        self.override_for(role)
            .cloned()
            .unwrap_or_else(|| role.default_model_id())
    }

    /// [`Self::resolve`], plus what ED-07's routing loop
    /// ([`crate::edit_distance::routing`]) knows about that model in
    /// `task_class`.
    ///
    /// The hint never changes the model returned. This door resolves exactly
    /// what [`Self::resolve`] resolves and hands the routing signal back
    /// beside it — the projection informs how a router WEIGHTS a candidate it
    /// is already willing to use, and there is no shape of hint that takes a
    /// role's model out of play.
    ///
    /// `None` is the default answer: a task class starts on
    /// [`RolloutRung::Shadow`] and stays there until an owner promotes it, so
    /// an engine that never touches the ladder routes exactly as it did before
    /// this door existed.
    ///
    /// [`RolloutRung::Shadow`]: crate::edit_distance::routing::RolloutRung::Shadow
    ///
    /// # Errors
    ///
    /// Storage errors reading the routing projection.
    pub fn resolve_with_routing_hint(
        &self,
        vault: &Vault,
        role: LlmRole,
        task_class: &str,
    ) -> Result<(ModelId, Option<WeightHint>)> {
        let model = self.resolve(role);
        let hint = routing_weight_hint(vault, &RoutingScopeKey::for_model(&model, task_class))?;
        Ok((model, hint))
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
/// per-call override -> vault policy manifest -> purpose default -> global.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierPrecedence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_call: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_policy: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_default: Option<ModelTierRef>,
    pub global_default: ModelTierRef,
}

impl TierPrecedence {
    #[must_use]
    pub fn resolved(&self) -> &ModelTierRef {
        self.per_call
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLocality {
    OnDevice,
    OwnServer,
    ThirdParty,
}
