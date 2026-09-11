//! AgentDefinition domain types, key/limit consts, and constructors.

use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::ModelTierRef;
use crate::pipeline::WorldScope;
use crate::skill::{SKILL_DEPENDENCY_KEYS, SkillDependency};
use rmpv::Value;

/// The pinned on-disk body keys for an `AgentDefinition`, in encode order.
///
/// `instructions`, `modelTier`, `world`, `ceiling`, `forkedFrom`, `logicalId`,
/// and `displayName` are optional and elided from the encoded map when absent
/// or default-valued (the elide-the-default pattern); every other key is
/// required. Decode rejects any key outside this set, so the schema is a
/// review-visible contract and hosts cannot add fields. A body with
/// `ceiling = proposed` (the default) and no fork lineage encodes
/// byte-identically to the pre-AGENT-2 17-key codec.
///
/// `enabled` is the SOLE always-encode exception (ONE-1890): a decode default
/// alone would let a seeded `enabled: true` row encode differently across
/// vaults, breaking byte-identical cross-vault seeding.
///
/// `memory_profile` (RT-05, ONE-1687) appends LAST and is elided when absent,
/// so a body written before it existed decodes with `memory_profile: None` and
/// re-encodes byte-for-byte.
pub const AGENT_DEF_BODY_KEYS: [&str; 23] = [
    "agentId",
    "desc",
    "version",
    "instructions",
    "skills",
    "connectors",
    "codeModeMcps",
    "modelTier",
    "scope",
    "world",
    "ceiling",
    "forkedFrom",
    "approvalStatus",
    "lifecycleStatus",
    "source",
    "confidence",
    "generated",
    "humanAuthored",
    "provenance",
    "logicalId",
    "enabled",
    "displayName",
    "memory_profile",
];

/// The pinned key pair for an [`McpRef`] sub-map.
pub const MCP_REF_KEYS: [&str; 2] = ["key", "minVersion"];

/// The pinned sub-map keys for a [`MemoryProfile`], in encode order.
pub const MEMORY_PROFILE_KEYS: [&str; 4] = [
    "window_token_budget",
    "budget_split",
    "compaction_backend",
    "compaction",
];

/// The pinned sub-map keys for a [`ContextBudgetSplit`], in encode order.
pub const CONTEXT_BUDGET_SPLIT_KEYS: [&str; 4] = ["claims", "turns", "summaries", "other"];

/// Maximum byte length of an `agent_id`.
pub const AGENT_ID_MAX_BYTES: usize = 256;

/// Maximum byte length of a `desc`.
pub const AGENT_DESC_MAX_BYTES: usize = 4096;

/// Maximum byte length of a `version` string (also reused for ref `min_version`).
pub const AGENT_VERSION_MAX_BYTES: usize = 128;

/// Maximum byte length of the optional `instructions` custom prompt.
pub const AGENT_INSTRUCTIONS_MAX_BYTES: usize = 16_384;

/// Maximum byte length of the optional `model_tier` reference string.
pub const AGENT_MODEL_TIER_MAX_BYTES: usize = 256;

/// Maximum byte length of a skill/connector/MCP reference id or key.
pub const AGENT_REF_KEY_MAX_BYTES: usize = 256;

/// Maximum number of entries in each composition list.
pub const AGENT_MAX_LIST_ENTRIES: usize = 64;

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

pub(super) const KEY_PROFILE_WINDOW_TOKEN_BUDGET: &str = MEMORY_PROFILE_KEYS[0];

pub(super) const KEY_PROFILE_BUDGET_SPLIT: &str = MEMORY_PROFILE_KEYS[1];

pub(super) const KEY_PROFILE_COMPACTION_BACKEND: &str = MEMORY_PROFILE_KEYS[2];

pub(super) const KEY_PROFILE_COMPACTION: &str = MEMORY_PROFILE_KEYS[3];

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

/// Maximum byte length of a `logical_id`.
pub(super) const AGENT_LOGICAL_ID_MAX_BYTES: usize = 256;

/// Maximum byte length of the runtime-editable `display_name`.
pub(super) const AGENT_DISPLAY_NAME_MAX_BYTES: usize = 256;

/// A versioned reference to a code-mode MCP, patterned on [`SkillDependency`].
///
/// `min_version` is the cheap forward hook for the OF-215 trajectory where MCPs
/// become versioned entities; today it is stored verbatim and never
/// existence-checked at write time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpRef {
    pub key: String,
    pub min_version: Option<String>,
}

impl McpRef {
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(key: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: Some(min_version.into()),
        }
    }
}

/// The run scope persisted with an `AgentDefinition`.
///
/// A new persisted descriptor rather than an embedded [`WorldScope`], which is
/// a runtime-only type that does not implement `Serialize`. `World` carries the
/// world's [`EntityId`], hex-encoded into the body. `WorldSet` is deliberately
/// not modelled here — it is a repo-clamp key with no day-1 caller, and a later
/// additive variant per the `#[non_exhaustive]` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentScope {
    /// Span every world (the constructor default; matches `PipelineBuilder`).
    All,
    /// Base-reality only.
    Base,
    /// This world plus base reality.
    World(EntityId),
}

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

/// The authored approval-ceiling bound persisted on an `AgentDefinition`
/// (OF-074: binary — the third trust tier is compositional, not a variant).
///
/// This is the agent's *self-limit*, not the owner's grant: effective
/// authority at every gate evaluation is `definition ceiling ∧ preset bound ∧
/// manifest actor_ceilings projection` (the meet across all three), so a
/// stored `Auto` never bypasses the owner-signed manifest. A persisted-
/// descriptor mirror of the gate's `PolicyApprovalCeiling` (which stays
/// `pub(crate)`); the conversion lives gate-side so this module never imports
/// gate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCeiling {
    Auto,
    Proposed,
}

impl AgentCeiling {
    /// The pinned wire string, matching `PolicyApprovalCeiling` vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Proposed => "proposed",
        }
    }

    /// Parses the pinned wire vocabulary (`"auto"` / `"proposed"`).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    /// True iff `self` requests wider authority than `bound` — the only
    /// ordering the no-widen rule ever needs.
    #[must_use]
    pub const fn widens_beyond(self, bound: Self) -> bool {
        matches!((self, bound), (Self::Auto, Self::Proposed))
    }
}

/// Who compacts an agent's context WINDOW (RT-05, ONE-1687).
///
/// MEMORY consolidation is the Dreamer's regardless of this flag — that half
/// is not a field, it is a law. This flag says only who owns the WINDOW, and
/// it follows execution ownership so a window is never double-compacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionOwnership {
    /// First-party code mode: the engine compacts the window.
    Engine,
    /// A bring-your-own-agent harness self-compacts; the engine NEVER touches
    /// its window.
    Byoa,
}

impl CompactionOwnership {
    /// Pinned wire string for [`Self::Engine`].
    pub const ENGINE: &'static str = "engine";
    /// Pinned wire string for [`Self::Byoa`].
    pub const BYOA: &'static str = "byoa";

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engine => Self::ENGINE,
            Self::Byoa => Self::BYOA,
        }
    }

    /// Parses the pinned wire vocabulary. Unknown strings are typed decode
    /// errors, never a default.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            Self::ENGINE => Ok(Self::Engine),
            Self::BYOA => Ok(Self::Byoa),
            _ => Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "memory_profile compaction must be one of engine|byoa",
            ))),
        }
    }
}

/// Optional per-entity-class share of the window budget.
///
/// Absent means the engine default split holds. Every fraction is validated
/// finite and strictly inside `(0.0, 1.0)`, and the four sum to `1.0 ± 1e-6`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ContextBudgetSplit {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl ContextBudgetSplit {
    #[must_use]
    pub const fn new(claims: f32, turns: f32, summaries: f32, other: f32) -> Self {
        Self {
            claims,
            turns,
            summaries,
            other,
        }
    }
}

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
        }
    }

    #[must_use]
    pub fn with_budget_split(mut self, split: ContextBudgetSplit) -> Self {
        self.budget_split = Some(split);
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
        }
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
