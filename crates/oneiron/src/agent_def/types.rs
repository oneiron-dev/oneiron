//! AgentDefinition domain types, key/limit consts, and constructors.

use super::models::AgentModel;
use super::optional_memory::OptionalMemoryProfile;
use super::refusal::RefusalDial;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::{ModelId, ModelTierRef};
use crate::pipeline::WorldScope;
use crate::skill::{SKILL_DEPENDENCY_KEYS, SkillDependency};
use rmpv::Value;

pub use crate::store::agent_record::AGENT_DEF_BODY_KEYS;

pub use crate::store::agent_record::MCP_REF_KEYS;

pub use crate::store::agent_record::AGENT_MODEL_KEYS;

pub use crate::store::agent_record::MEMORY_PROFILE_KEYS;

/// The `memory_profile.compaction_backend` value that makes an agent its own
/// compaction writer (FIX 4465): each epoch and fold summary is written AS
/// the agent, wearing its home, under its byline. It names WHO writes, never
/// a model: the model and context come per wake from the purpose-default
/// table's self-compaction row. Every other key keeps its backend unchanged.
pub(crate) const SELF_COMPACTION_BACKEND: &str = "self";

/// The pinned sub-map keys for a profile's `output_decay`, in encode order.
pub(super) const OUTPUT_DECAY_KEYS: [&str; 2] = ["overview_after_turns", "stub_after_turns"];

/// Bytes of one verbatim pin past which a put asks (the length it once
/// refused past); a pin of any length is kept, as any number of pins is.
pub(super) const MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES: usize = 1024;

pub use crate::store::agent_record::CONTEXT_BUDGET_SPLIT_KEYS;

pub use crate::store::agent_record::AGENT_ID_MAX_BYTES;

pub use crate::store::agent_record::AGENT_DESC_MAX_BYTES;

pub use crate::store::agent_record::AGENT_VERSION_MAX_BYTES;

pub use crate::store::agent_record::AGENT_INSTRUCTIONS_MAX_BYTES;

pub use crate::store::agent_record::AGENT_MODEL_TIER_MAX_BYTES;

pub use crate::store::agent_record::AGENT_REF_KEY_MAX_BYTES;

pub use crate::store::agent_record::AGENT_MAX_LIST_ENTRIES;

pub(super) const KEY_AGENT_ID: &str = AGENT_DEF_BODY_KEYS[0];

pub(super) const KEY_DESC: &str = AGENT_DEF_BODY_KEYS[1];

pub(super) const KEY_VERSION: &str = AGENT_DEF_BODY_KEYS[2];

pub(super) const KEY_INSTRUCTIONS: &str = AGENT_DEF_BODY_KEYS[3];

pub(super) const KEY_SKILLS: &str = AGENT_DEF_BODY_KEYS[4];

pub(super) const KEY_CONNECTORS: &str = AGENT_DEF_BODY_KEYS[5];

pub(super) const KEY_CODE_MODE_MCPS: &str = AGENT_DEF_BODY_KEYS[6];

pub(super) const KEY_MODEL_TIER: &str = AGENT_DEF_BODY_KEYS[7];

pub(super) const KEY_SCOPE: &str = AGENT_DEF_BODY_KEYS[8];

pub(super) const KEY_WORLD: &str = AGENT_DEF_BODY_KEYS[9];

pub(super) const KEY_CEILING: &str = AGENT_DEF_BODY_KEYS[10];

pub(super) const KEY_FORKED_FROM: &str = AGENT_DEF_BODY_KEYS[11];

pub(super) const KEY_APPROVAL_STATUS: &str = AGENT_DEF_BODY_KEYS[12];

pub(super) const KEY_LIFECYCLE_STATUS: &str = AGENT_DEF_BODY_KEYS[13];

pub(super) const KEY_SOURCE: &str = AGENT_DEF_BODY_KEYS[14];

pub(super) const KEY_CONFIDENCE: &str = AGENT_DEF_BODY_KEYS[15];

pub(super) const KEY_GENERATED: &str = AGENT_DEF_BODY_KEYS[16];

pub(super) const KEY_HUMAN_AUTHORED: &str = AGENT_DEF_BODY_KEYS[17];

pub(super) const KEY_PROVENANCE: &str = AGENT_DEF_BODY_KEYS[18];

pub(super) const KEY_LOGICAL_ID: &str = AGENT_DEF_BODY_KEYS[19];

pub(super) const KEY_ENABLED: &str = AGENT_DEF_BODY_KEYS[20];

pub(super) const KEY_DISPLAY_NAME: &str = AGENT_DEF_BODY_KEYS[21];

pub(super) const KEY_MEMORY_PROFILE: &str = AGENT_DEF_BODY_KEYS[22];

pub(super) const KEY_DREAMING: &str = AGENT_DEF_BODY_KEYS[23];

pub(super) const KEY_DREAMING_MODEL: &str = AGENT_DEF_BODY_KEYS[24];
pub(super) const KEY_WAKE_CADENCE: &str = AGENT_DEF_BODY_KEYS[25];

pub(super) const KEY_REFUSAL: &str = AGENT_DEF_BODY_KEYS[26];

pub(super) const KEY_MODELS: &str = AGENT_DEF_BODY_KEYS[27];

pub(super) const KEY_COMPACTION_MODEL: &str = AGENT_DEF_BODY_KEYS[28];

pub(super) const KEY_MODEL_REF: &str = AGENT_MODEL_KEYS[0];

pub(super) const KEY_MODEL_WHEN: &str = AGENT_MODEL_KEYS[1];

pub(super) const KEY_PROFILE_WINDOW_TOKEN_BUDGET: &str = MEMORY_PROFILE_KEYS[0];

pub(super) const KEY_PROFILE_BUDGET_SPLIT: &str = MEMORY_PROFILE_KEYS[1];

pub(super) const KEY_PROFILE_COMPACTION_BACKEND: &str = MEMORY_PROFILE_KEYS[2];

pub(super) const KEY_PROFILE_COMPACTION: &str = MEMORY_PROFILE_KEYS[3];

pub(super) const KEY_PROFILE_HOT_STEPS: &str = MEMORY_PROFILE_KEYS[4];

pub(super) const KEY_PROFILE_OUTPUT_DECAY: &str = MEMORY_PROFILE_KEYS[5];

pub(super) const KEY_PROFILE_VERBATIM_PINS: &str = MEMORY_PROFILE_KEYS[6];

pub(super) const KEY_PROFILE_OPTIONAL_MEMORY: &str = MEMORY_PROFILE_KEYS[7];

pub(super) const KEY_SPLIT_CLAIMS: &str = CONTEXT_BUDGET_SPLIT_KEYS[0];

pub(super) const KEY_SPLIT_TURNS: &str = CONTEXT_BUDGET_SPLIT_KEYS[1];

pub(super) const KEY_SPLIT_SUMMARIES: &str = CONTEXT_BUDGET_SPLIT_KEYS[2];

pub(super) const KEY_SPLIT_OTHER: &str = CONTEXT_BUDGET_SPLIT_KEYS[3];

pub(super) const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];

pub(super) const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

pub(super) const KEY_MCP_KEY: &str = MCP_REF_KEYS[0];

pub(super) const KEY_MCP_MIN_VERSION: &str = MCP_REF_KEYS[1];

pub(super) const SCOPE_ALL: &str = "all";

pub(super) const SCOPE_BASE: &str = "base";

pub(super) const SCOPE_WORLD: &str = "world";

/// Reserved logical-id prefix for seeded system rows. Enforced at the
/// AGENT_DEF put-decode chokepoint (`batch.rs::apply_put`), which is the only
/// place that holds both the body and the row id it is being stored at.
pub(super) const SYSTEM_LOGICAL_ID_PREFIX: &str = "sys.";

/// Bytes of a `logical_id` past which a put asks; any length is kept.
pub(super) const AGENT_LOGICAL_ID_MAX_BYTES: usize = 256;

/// Bytes of the runtime-editable `display_name` past which a put asks.
pub(super) const AGENT_DISPLAY_NAME_MAX_BYTES: usize = 256;

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

    pub(super) fn discriminant(&self) -> &'static str {
        match self {
            Self::All => SCOPE_ALL,
            Self::Base => SCOPE_BASE,
            Self::World(_) => SCOPE_WORLD,
        }
    }
}

pub use crate::store::agent_record::{
    AgentCeiling, AgentWakeCadence, CompactionOwnership, ContextBudgetSplit, DreamingMode,
};

/// The per-agent context-window memory profile (RT-05, ONE-1687).
///
/// Additive and optional: an `AgentDefinition` carrying `None` reproduces
/// today's behavior byte-for-byte, so the record grew without moving any
/// existing agent's assembly.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct MemoryProfile {
    /// Context-window token budget for this agent — the lift of
    /// `context_pack`'s builder-constant default.
    pub window_token_budget: u64,
    /// Optional per-entity-class split; absent = the engine default split.
    pub budget_split: Option<ContextBudgetSplit>,
    /// Host-registered compaction backend key. Resolved against the
    /// compaction registry at drive time; never a frontier tier. The ban is
    /// enforced at registration, not by sniffing this string.
    pub compaction_backend: ModelTierRef,
    /// Who compacts this agent's context WINDOW.
    pub compaction: CompactionOwnership,
    /// How many recent steps stay raw past a compaction (agent-runtime-v1
    /// #d7 hot window, Docs Q13); absent = the host's configured hot window.
    pub hot_steps: Option<u64>,
    /// When a stored output decays to its overview, then to a stub, in turns
    /// (#d7 decay thresholds); absent = the executor's default decay.
    pub output_decay: Option<crate::compaction::output::OutputDecayPolicy>,
    /// Literal text every summary of this agent's window keeps verbatim when
    /// the span holds it (#d7 verbatim pins). User messages and failure lines
    /// stay pinned regardless; these are added, never a replacement.
    pub verbatim_pins: Vec<String>,
    /// The optional recall this reader takes per task family; absent = the
    /// caller's request as sent. Separate from the window above.
    pub optional_memory: Option<OptionalMemoryProfile>,
}

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

/// A saved, host-agnostic agent composition record.
///
/// The lifecycle block (`approval_status` … `provenance`) is the shared
/// `SkillRecord` machinery, field-for-field. `generated`/`human_authored` are a
/// mutually-exclusive authorship pair and `generated` tracks
/// `source == ClaimSource::Generated`; both invariants are frozen on update.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AgentDefinition {
    pub agent_id: String,
    pub desc: String,
    pub version: String,
    pub instructions: Option<String>,
    pub skills: Vec<SkillDependency>,
    pub connectors: Vec<String>,
    pub code_mode_mcps: Vec<McpRef>,
    pub model_tier: Option<ModelTierRef>,
    pub scope: AgentScope,
    pub ceiling: AgentCeiling,
    /// The fork parent's stored row id. Frozen on update.
    pub forked_from: Option<EntityId>,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: ClaimLifecycleStatus,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub provenance: Value,
    /// Stable lookup key for a seeded row (`sys.*`). User-created definitions
    /// carry `None`; once `Some`, it is frozen on update.
    pub logical_id: Option<String>,
    /// Whether this definition may be dispatched. Row state, not absence —
    /// reseeding never resurrects a user's "off".
    pub enabled: bool,
    /// Runtime-editable display name; deliberately NOT in the freeze-set.
    pub display_name: Option<String>,
    /// Per-agent context-window memory profile (RT-05, ONE-1687). A dial, not
    /// identity: it may change on update under the ordinary version-bump rule,
    /// so it is deliberately NOT in the freeze-set.
    pub memory_profile: Option<MemoryProfile>,
    /// Absent means enabled and inheriting the vault weaver model and window.
    pub dreaming: Option<DreamingMode>,
    /// Optional per-resident model slot for `Own` dreaming. Host-resolved.
    pub dreaming_model: Option<ModelTierRef>,
    /// An absent role follows the owner-editable wake-policy absent-role row.
    pub wake_cadence: Option<AgentWakeCadence>,
    /// Her refusal dial (OF-533). Absent, or a domain left unset, takes the
    /// vault-kind default; resolve through [`super::resolve_refusal`]. A
    /// dial, not identity: deliberately NOT in the freeze-set.
    pub refusal: Option<RefusalDial>,
    /// The models the agent may run on, in its owner's order, each with the
    /// owner's words on when (FIX 4472). Empty: its one house-routed model.
    /// A dial, not identity: deliberately NOT in the freeze-set.
    pub models: Vec<AgentModel>,
    /// The model that compacts the agent's window; absent takes the default
    /// its host supplies (for a `self` writer, the self-compaction row's
    /// cheap model, FIX 6029). It need not be listed; resolve through
    /// [`super::resolve_compaction_model`].
    pub compaction_model: Option<ModelId>,
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

/// The canonical seeded system-agent roster (OF-334 / ONE-1890): data, not a
/// compiled enum. Every baseline row is an ordinary byte-17 `AGENT_DEF` entity
/// with a pinned row id, a pinned actor id equal to it, and a stable `sys.*`
/// logical id. ONE-1709 appends `sys.team_lead` to this same file.
pub(super) const SYSTEM_AGENT_DEFINITIONS_V1_JSON: &str =
    include_str!("data/system_agent_definitions.v1.json");

/// Seam shim (SEAM-GATE-PRESET-NEUTRALIZATION): gate.rs resolves a fork parent
/// through ONE call. Post-ONE-1890 `forked_from` already IS the parent row id,
/// so the shim is identity over `EntityId` — kept so gate.rs never re-spells
/// the lineage seam.
pub(crate) fn forked_from_row_ref(forked_from: &EntityId) -> EntityId {
    *forked_from
}
