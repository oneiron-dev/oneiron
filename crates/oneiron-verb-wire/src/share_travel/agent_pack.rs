//! Moved from `crates/oneiron/src/share_travel/agent_pack.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::agent_refusal::RefusalDial;
use crate::store::agent_refusal::RefusalLevel;
use oneiron_authority::share_travel::BornWith;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelTierRef;
use oneiron_store::agent_model::AgentModel;
use oneiron_store::agent_record::AgentCeiling;
use oneiron_store::agent_record::CompactionOwnership;
use oneiron_store::serialize::pack_format::FieldProfile;
use oneiron_store::write_envelope::skill_record::identity::SkillContentHash;
use oneiron_store::write_envelope::skill_record::identity::canonical_skill_tree_hash;
use oneiron_store::write_envelope::skill_record::lifecycle::SkillLifecycle;
use oneiron_store::write_envelope::skill_record::record::SkillDependency;
use oneiron_store::write_envelope::skill_record::record::SkillRecord;
use oneiron_store::write_envelope::skill_record::role::SkillCallContract;
use oneiron_store::write_envelope::skill_record::role::SkillRole;
use oneiron_store::write_envelope::skill_source::HubFile;
use oneiron_store::write_envelope::skill_source::SkillPackageFormat;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroU64;

/// The run scope, with a world named rather than referenced. The destination
/// binds a local world by that name or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackScope {
    All,
    Base,
    World { name: String },
}

/// The agent's own approval ceiling: a self-limit, never a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackCeiling {
    Auto,
    Proposed,
}

/// A code-mode MCP the agent asks for, by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackMcp {
    pub key: String,
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackCompaction {
    Engine,
    Byoa,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackBudgetSplit {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackOutputDecay {
    pub overview_after_turns: u64,
    pub stub_after_turns: u64,
}

/// The detail an optional recall reads at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackView {
    Minimal,
    Standard,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackOptionalMemory {
    None,
    Budget {
        tokens: NonZeroU64,
        view: AgentPackView,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackOptionalMemoryProfile {
    pub default: AgentPackOptionalMemory,
    pub families: BTreeMap<String, AgentPackOptionalMemory>,
}

/// The agent's context-window memory profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackMemoryProfile {
    pub window_token_budget: u64,
    pub budget_split: Option<AgentPackBudgetSplit>,
    /// A compaction backend key the destination resolves in its own registry.
    pub compaction_backend: String,
    pub compaction: AgentPackCompaction,
    pub hot_steps: Option<u64>,
    pub output_decay: Option<AgentPackOutputDecay>,
    pub verbatim_pins: Vec<String>,
    pub optional_memory: Option<AgentPackOptionalMemoryProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackDreaming {
    Own,
    Inherit,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPackWakeCadence {
    Companion { every_turns: Option<u64> },
    Leader { every_turns: Option<u64> },
    Worker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackRefusalLevel {
    None,
    Voice,
    Veto,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackRefusal {
    pub bond: Option<AgentPackRefusalLevel>,
    pub logistics: Option<AgentPackRefusalLevel>,
}

impl From<RefusalDial> for AgentPackRefusal {
    fn from(value: RefusalDial) -> Self {
        Self {
            bond: value.bond.map(Into::into),
            logistics: value.logistics.map(Into::into),
        }
    }
}

impl From<AgentPackRefusal> for RefusalDial {
    fn from(value: AgentPackRefusal) -> Self {
        Self {
            bond: value.bond.map(Into::into),
            logistics: value.logistics.map(Into::into),
        }
    }
}

/// The configuration the agent asks for. Every field is a request the
/// destination meets against its own grants; none confers authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackPolicy {
    pub scope: AgentPackScope,
    pub ceiling: AgentPackCeiling,
    /// Connector names; the destination resolves its own.
    pub connectors: Vec<String>,
    pub code_mode_mcps: Vec<AgentPackMcp>,
    pub model_tier: Option<String>,
    pub memory_profile: Option<AgentPackMemoryProfile>,
    pub dreaming: Option<AgentPackDreaming>,
    pub dreaming_model: Option<String>,
    pub wake_cadence: Option<AgentPackWakeCadence>,
    pub refusal: Option<AgentPackRefusal>,
    /// The models the agent runs on, each with when (FIX 4472); the
    /// destination seats only those its own catalog serves.
    pub models: Vec<AgentModel>,
    pub compaction_model: Option<ModelId>,
}

/// How a travelling skill's source fields relate to its native metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackSkillFormat {
    Folder,
    Native,
}

impl From<SkillPackageFormat> for AgentPackSkillFormat {
    fn from(format: SkillPackageFormat) -> Self {
        match format {
            SkillPackageFormat::Folder => Self::Folder,
            SkillPackageFormat::Native => Self::Native,
        }
    }
}

/// A skill's native role, carried without granting its authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPackSkillRole {
    Knowledge,
    Workflow,
    Callable,
}

impl From<SkillRole> for AgentPackSkillRole {
    fn from(role: SkillRole) -> Self {
        match role {
            SkillRole::Knowledge => Self::Knowledge,
            SkillRole::Workflow => Self::Workflow,
            SkillRole::Callable => Self::Callable,
        }
    }
}

/// The executable call contract a callable skill carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackSkillCall {
    pub reference: String,
    pub arguments: serde_json::Value,
    pub returns: serde_json::Value,
}

impl From<&SkillCallContract> for AgentPackSkillCall {
    fn from(call: &SkillCallContract) -> Self {
        Self {
            reference: call.reference.clone(),
            arguments: call.arguments.clone(),
            returns: call.returns.clone(),
        }
    }
}

/// A reference-free skill dependency: its id and version floor, never an
/// entity ref (FIX 3276).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackSkillDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

impl From<&SkillDependency> for AgentPackSkillDependency {
    fn from(dependency: &SkillDependency) -> Self {
        Self {
            skill_id: dependency.skill_id.clone(),
            min_version: dependency.min_version.clone(),
        }
    }
}

/// One `skills.json` row: a skill dependency and the native metadata its
/// receiver needs, pinned by content hash (FIX 3276).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackSkillRef {
    pub skill_id: String,
    pub version: String,
    pub min_version: Option<String>,
    /// `canonical_skill_tree_hash` over the skill's files, lowercase hex.
    pub content_hash: String,
    pub format: AgentPackSkillFormat,
    pub desc: String,
    pub role: AgentPackSkillRole,
    pub call: Option<AgentPackSkillCall>,
    pub dependencies: Vec<AgentPackSkillDependency>,
}

/// One selected piece of knowledge about the agent, as text. The destination
/// mints it as a local claim with this agent as the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackKnowledge {
    pub predicate: String,
    pub text: String,
}
