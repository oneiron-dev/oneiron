//! Stored agent descriptors, schema keys and byte-observation thresholds.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

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
/// `memory_profile` (RT-05, ONE-1687) and the dreaming mode/model fields
/// append in that order and are elided when absent, so older bodies re-encode
/// byte-for-byte. Absent dreaming means inherit, on by default.
///
/// `refusal` (OF-533) appends next and is elided when absent; absent means
/// every domain sits at the vault-kind default.
///
/// `models` and `compaction_model` (FIX 4472) append last, elided when empty
/// or absent: no list runs the agent on its one house-routed model, and no
/// compaction model takes the house's.
pub const AGENT_DEF_BODY_KEYS: [&str; 29] = [
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
    "dreaming",
    "dreamingModel",
    "wakeCadence",
    "refusal",
    "models",
    "compaction_model",
];

/// The pinned key pair for an [`McpRef`] sub-map.
pub const MCP_REF_KEYS: [&str; 2] = ["key", "minVersion"];

/// The pinned key pair for one [`AgentModel`] entry, in encode order.
pub const AGENT_MODEL_KEYS: [&str; 2] = ["model_ref", "when"];

/// The pinned sub-map keys for a [`MemoryProfile`], in encode order.
pub const MEMORY_PROFILE_KEYS: [&str; 8] = [
    "window_token_budget",
    "budget_split",
    "compaction_backend",
    "compaction",
    "hot_steps",
    "output_decay",
    "verbatim_pins",
    "optional_memory",
];

/// The pinned sub-map keys for a [`ContextBudgetSplit`], in encode order.
pub const CONTEXT_BUDGET_SPLIT_KEYS: [&str; 4] = ["claims", "turns", "summaries", "other"];

/// Bytes of an `agent_id` past which a put asks; any length is kept.
pub const AGENT_ID_MAX_BYTES: usize = 256;

/// Bytes of a `desc` past which a put asks; any length is kept.
pub const AGENT_DESC_MAX_BYTES: usize = 4096;

/// Bytes of a `version` (or a ref's `min_version`) past which a put asks.
pub const AGENT_VERSION_MAX_BYTES: usize = 128;

/// Bytes of the optional `instructions` past which a put asks; any are kept.
pub const AGENT_INSTRUCTIONS_MAX_BYTES: usize = 16_384;

/// Bytes of a `model_tier` or model reference past which a put asks.
pub const AGENT_MODEL_TIER_MAX_BYTES: usize = 256;

/// Bytes of a skill/connector/MCP id or key past which a put asks.
pub const AGENT_REF_KEY_MAX_BYTES: usize = 256;

/// Entries in one composition list past which a definition's put asks
/// whether everything is okay (the count it once refused past); every entry
/// is kept, however many (rule 5).
pub const AGENT_MAX_LIST_ENTRIES: usize = 64;

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
