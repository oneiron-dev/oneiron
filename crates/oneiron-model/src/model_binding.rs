//! Model-role bindings and calibrated verdict values.

use crate::llm::{ModelId, ModelLocality, ModelTierRef};
use oneiron_contracts::claim::{ConfidenceBand, VerdictBasis};
use oneiron_contracts::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    RetrievalEmbedder,
    MediaEmbedder,
    Reranker,
    ExtractionEncoder,
    ExtractionTeacher,
    GenerativeReasoner,
    /// The full-local default's reasoner: answers verdict and generate calls
    /// through the LLM slot when the route is narrowed to the device or an
    /// owned endpoint (ARCH-0036 r9 product pins).
    LocalReasoner,
    Checker,
    DecisionHead,
    DecisionBand,
    DecisionEscalation,
    PolicySafeguard,
    DreamerCurrent,
    DreamerTarget,
    /// Optional until the owner binds a checkpoint from a training pack.
    DreamerDistilled,
    Asr,
    Captioner,
    DocParsing,
    AudioVad,
    TtsDeferred,
    /// The Local-vision slot's small vision model: reads an image's full
    /// pixels and answers a question about them in text or a Box as the
    /// Local rung (`ask_image`, OF-329), through the LLM slot. No model is
    /// chosen for it.
    LocalVision,
    /// The Coach's own seat (agent-mind AGM-5): its agent-health asks,
    /// code-fix drafts and session-end distill. Optional: with no seat of its
    /// own the Coach rides the generative reasoner's.
    Coach,
    /// The browser planner (CUA E5): the mid planner a browser subgoal's
    /// next code-mode step runs on once a batch or library run of it ends
    /// `NEEDS_AGENT`. Optional: with no seat or manifest row of its own the
    /// step stays on the generative reasoner's. No model is chosen for it.
    BrowserPlanner,
}
pub const MODEL_ROLES: [ModelRole; 23] = [
    ModelRole::RetrievalEmbedder,
    ModelRole::MediaEmbedder,
    ModelRole::Reranker,
    ModelRole::ExtractionEncoder,
    ModelRole::ExtractionTeacher,
    ModelRole::GenerativeReasoner,
    ModelRole::LocalReasoner,
    ModelRole::Checker,
    ModelRole::DecisionHead,
    ModelRole::DecisionBand,
    ModelRole::DecisionEscalation,
    ModelRole::PolicySafeguard,
    ModelRole::DreamerCurrent,
    ModelRole::DreamerTarget,
    ModelRole::DreamerDistilled,
    ModelRole::Asr,
    ModelRole::Captioner,
    ModelRole::DocParsing,
    ModelRole::AudioVad,
    ModelRole::TtsDeferred,
    ModelRole::LocalVision,
    ModelRole::Coach,
    ModelRole::BrowserPlanner,
];
impl ModelRole {
    /// A role of the generative family: it generates or rules through the
    /// model line, never tags (ARCH-0036 "two model families").
    #[must_use]
    pub const fn is_generative(self) -> bool {
        matches!(
            self,
            Self::GenerativeReasoner
                | Self::LocalReasoner
                | Self::Checker
                | Self::DecisionHead
                | Self::DecisionBand
                | Self::DecisionEscalation
                | Self::PolicySafeguard
                | Self::DreamerCurrent
                | Self::DreamerTarget
                | Self::DreamerDistilled
                | Self::ExtractionTeacher
                | Self::Coach
                | Self::BrowserPlanner
        )
    }
    /// A role a v2 manifest may leave unbound. Media, decision and safeguard
    /// roles have independent bindings with no implicit fallback. The trained
    /// checkpoint may be unbound; the Coach and browser planner fall back to
    /// the chat seat.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(
            self,
            Self::DreamerDistilled
                | Self::Coach
                | Self::BrowserPlanner
                | Self::MediaEmbedder
                | Self::DecisionHead
                | Self::DecisionBand
                | Self::DecisionEscalation
                | Self::PolicySafeguard
        )
    }
    /// The disposition a row that names none takes: the extraction teacher
    /// is offline, every other role served (ARCH-0036 "one base, two roles").
    #[must_use]
    pub const fn default_disposition(self) -> ModelDisposition {
        if matches!(self, Self::ExtractionTeacher) {
            ModelDisposition::Offline
        } else {
            ModelDisposition::Served
        }
    }
}
/// Whether a role's model answers served calls. An offline role teaches the
/// tagger and runs background passes (extraction, consolidation, eval); it
/// never serves a turn. An owner who routes a seat to it marks its row
/// `served` and pays its cost (owner, 2026-10-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelDisposition {
    Offline,
    Served,
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ModelSlot {
    Llm,
    Embedder,
    Oneironer,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBinding {
    pub model: ModelId,
    pub slot: ModelSlot,
    pub tier: ModelTierRef,
    /// Explicit identities for narrower routes; a model ID has one catalog locality.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub route_models: BTreeMap<ModelLocality, ModelId>,
    /// Offline or served; absent takes [`ModelRole::default_disposition`].
    /// The teacher's binding hash covers it, so serving the teacher needs a
    /// probe approval of that served row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<ModelDisposition>,
    /// Whether the bound model, on every route this binding names, hears audio
    /// clips on the chat wire. A decision rung over the role reads audio only
    /// when this says so and the served model's catalog row admits
    /// [`crate::llm::LlmCapability::AudioInput`]; absent is false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reads_audio: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictMode {
    Shadow,
    Enforce,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerdictBinding {
    #[schemars(with = "String")]
    pub model: ModelId,
    pub slot: ModelSlot,
    pub floor: ConfidenceBand,
    pub mode: VerdictMode,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibratedVerdict {
    pub model: ModelId,
    pub allow: bool,
    pub confidence_millionths: u32,
    pub band: ConfidenceBand,
    pub basis: VerdictBasis,
}
impl CalibratedVerdict {
    /// The verdict's own shape: a confidence of at most one, in millionths.
    /// Its band is the producer's, kept as given: no fixed cutoff table
    /// rewrites or refuses it (FIX 7761).
    pub fn validate(&self) -> Result<()> {
        if self.confidence_millionths > 1_000_000 {
            return Err(invalid("verdict confidence is past one"));
        }
        Ok(())
    }
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}
