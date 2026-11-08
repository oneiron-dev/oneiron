//! AgentDefinition domain types, key/limit consts, and constructors.

use super::models::AgentModel;
use super::optional_memory::OptionalMemoryProfile;
use super::refusal::RefusalDial;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::{ModelId, ModelTierRef};
use crate::pipeline::WorldScope;
use crate::skill::SkillDependency;
use rmpv::Value;

pub use crate::store::agent_record::AGENT_DEF_BODY_KEYS;

pub use crate::store::agent_record::MCP_REF_KEYS;

pub use crate::store::agent_record::AGENT_MODEL_KEYS;

pub use crate::store::agent_record::MEMORY_PROFILE_KEYS;

pub(super) use crate::store::agent_definition_codec::keys::MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES;

/// The `memory_profile.compaction_backend` value that makes an agent its own
/// compaction writer (FIX 4465): each epoch and fold summary is written AS
/// the agent, wearing its home, under its byline. It names WHO writes, never
/// a model: the model and context come per wake from the purpose-default
/// table's self-compaction row. Every other key keeps its backend unchanged.
pub(crate) const SELF_COMPACTION_BACKEND: &str = "self";

pub use crate::store::agent_record::CONTEXT_BUDGET_SPLIT_KEYS;

pub use crate::store::agent_record::AGENT_ID_MAX_BYTES;

pub use crate::store::agent_record::AGENT_DESC_MAX_BYTES;

pub use crate::store::agent_record::AGENT_VERSION_MAX_BYTES;

pub use crate::store::agent_record::AGENT_INSTRUCTIONS_MAX_BYTES;

pub use crate::store::agent_record::AGENT_MODEL_TIER_MAX_BYTES;

pub use crate::store::agent_record::AGENT_REF_KEY_MAX_BYTES;

pub use crate::store::agent_record::AGENT_MAX_LIST_ENTRIES;

pub(super) use crate::store::agent_manifest::{
    AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, SYSTEM_AGENT_DEFINITIONS_V1_JSON,
};

pub use crate::store::agent_record::McpRef;

pub use crate::store::agent_scope::AgentScope;

impl AgentScope {
    /// Maps to the runtime [`WorldScope`] a dispatch layer (AGENT-3) reconstitutes.
    #[must_use]
    pub fn to_world_scope(&self) -> WorldScope {
        match self {
            Self::All => WorldScope::All,
            Self::Base => WorldScope::Base,
            Self::World(world) => WorldScope::World(*world),
        }
    }
}

pub use crate::store::agent_record::{
    AgentCeiling, AgentWakeCadence, CompactionOwnership, ContextBudgetSplit, DreamingMode,
};

pub use crate::store::agent_memory_profile::MemoryProfile;

pub use crate::store::agent_definition::AgentDefinition;

impl MemoryProfile {
    #[must_use]
    pub const fn new(
        window_token_budget: u64,
        compaction_backend: ModelTierRef,
        compaction: CompactionOwnership,
    ) -> Self {
        Self {
            window_token_budget,
            budget_split: None,
            compaction_backend,
            compaction,
            hot_steps: None,
            output_decay: None,
            verbatim_pins: Vec::new(),
            optional_memory: None,
        }
    }

    /// This profile written as its agent (FIX 7744): the same window, split,
    /// hot window, decay and pins, with the reserved `SELF_COMPACTION_BACKEND`
    /// key as its backend and the engine owning the window. An engine-run
    /// agent whose definition carries no profile compacts by its host's
    /// profile made so.
    #[must_use]
    pub fn as_self_writer(mut self) -> Self {
        self.compaction_backend = ModelTierRef(SELF_COMPACTION_BACKEND.to_owned());
        self.compaction = CompactionOwnership::Engine;
        self
    }

    /// Whether this agent writes its own compaction: its profile names the
    /// reserved `SELF_COMPACTION_BACKEND` key. Nothing else turns it on.
    #[must_use]
    pub fn writes_as_self(&self) -> bool {
        self.compaction_backend.as_str() == SELF_COMPACTION_BACKEND
    }

    #[must_use]
    pub const fn with_hot_steps(mut self, hot_steps: u64) -> Self {
        self.hot_steps = Some(hot_steps);
        self
    }

    #[must_use]
    pub const fn with_output_decay(
        mut self,
        decay: crate::compaction::output::OutputDecayPolicy,
    ) -> Self {
        self.output_decay = Some(decay);
        self
    }

    #[must_use]
    pub fn with_verbatim_pins(mut self, pins: Vec<String>) -> Self {
        self.verbatim_pins = pins;
        self
    }

    #[must_use]
    pub fn with_budget_split(mut self, split: ContextBudgetSplit) -> Self {
        self.budget_split = Some(split);
        self
    }

    #[must_use]
    pub fn with_optional_memory(mut self, optional_memory: OptionalMemoryProfile) -> Self {
        self.optional_memory = Some(optional_memory);
        self
    }
}

impl AgentDefinition {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors the pinned AGENT_DEF record fields"
    )]
    #[must_use]
    pub fn new(
        agent_id: impl Into<String>,
        desc: impl Into<String>,
        version: impl Into<String>,
        instructions: Option<String>,
        skills: Vec<SkillDependency>,
        connectors: Vec<String>,
        code_mode_mcps: Vec<McpRef>,
        model_tier: Option<ModelTierRef>,
        scope: AgentScope,
        ceiling: AgentCeiling,
        forked_from: Option<EntityId>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: ClaimLifecycleStatus,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        provenance: Value,
        logical_id: Option<String>,
        enabled: bool,
        display_name: Option<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            desc: desc.into(),
            version: version.into(),
            instructions,
            skills,
            connectors,
            code_mode_mcps,
            model_tier,
            scope,
            ceiling,
            forked_from,
            approval_status,
            lifecycle_status,
            source,
            confidence,
            generated,
            human_authored,
            provenance,
            logical_id,
            enabled,
            display_name,
            memory_profile: None,
            dreaming: None,
            dreaming_model: None,
            wake_cadence: None,
            refusal: None,
            models: Vec::new(),
            compaction_model: None,
        }
    }

    /// Resolve this definition's due decision against the live policy row.
    /// Absence, role triggers and precedence are owner-editable policy data.
    #[must_use]
    pub fn dream_wake_due(
        &self,
        policy: &crate::dreamer_wake::DreamerWakePolicy,
        turn_ordinal: u64,
        signals: crate::dreamer_wake::AgentWakeSignals,
    ) -> bool {
        policy
            .agent_cadence
            .due(self, policy.wake_grain_turns, turn_ordinal, signals)
    }

    #[must_use]
    pub fn with_wake_cadence(mut self, cadence: AgentWakeCadence) -> Self {
        self.wake_cadence = Some(cadence);
        self
    }

    /// Sets the refusal dial (OF-533); `None` returns every domain to the
    /// vault-kind default.
    #[must_use]
    pub fn with_refusal(mut self, refusal: Option<RefusalDial>) -> Self {
        self.refusal = refusal;
        self
    }

    /// Sets the owner's model list (FIX 4472); empty returns the agent to
    /// its one house-routed model.
    #[must_use]
    pub fn with_models(mut self, models: Vec<AgentModel>) -> Self {
        self.models = models;
        self
    }

    /// Sets the model that compacts the agent's window; `None` takes the
    /// house's.
    #[must_use]
    pub fn with_compaction_model(mut self, model: Option<ModelId>) -> Self {
        self.compaction_model = model;
        self
    }

    /// Effective setting: an absent key is inherit, ON by default.
    #[must_use]
    pub fn dreaming_mode(&self) -> DreamingMode {
        self.dreaming.unwrap_or(DreamingMode::Inherit)
    }

    /// Attaches the RT-05 [`MemoryProfile`] (ONE-1687).
    ///
    /// Deliberately a builder step rather than a 22nd constructor parameter:
    /// `new` mirrors the pre-RT-05 record and every existing call site keeps
    /// compiling unchanged, so the additive-and-elided profile discipline
    /// reaches the constructor too. `None` is the no-op that reproduces
    /// today's record byte-for-byte.
    #[must_use]
    pub fn with_memory_profile(mut self, memory_profile: Option<MemoryProfile>) -> Self {
        self.memory_profile = memory_profile;
        self
    }

    #[must_use]
    pub fn with_dreaming(
        mut self,
        mode: Option<DreamingMode>,
        model: Option<ModelTierRef>,
    ) -> Self {
        self.dreaming = mode;
        self.dreaming_model = model;
        self
    }
}

/// Seam shim (SEAM-GATE-PRESET-NEUTRALIZATION): gate.rs resolves a fork parent
/// through ONE call. Post-ONE-1890 `forked_from` already IS the parent row id,
/// so the shim is identity over `EntityId` — kept so gate.rs never re-spells
/// the lineage seam.
pub(crate) fn forked_from_row_ref(forked_from: &EntityId) -> EntityId {
    *forked_from
}
