//! Moved from `crates/oneiron/src/memory/recall/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::affect::QueryAffect;
pub use crate::memory::recall::call_mode::RecallEffort;
pub use crate::memory::recall::home::RecallResidenceHit;
pub use crate::memory::recall::home::RecallResidenceSource;
pub use crate::memory::recall::paid::RerankReport;
pub use crate::memory::recall::paid::RerankSkip;
use crate::retrieval_depth::controls::RecallTelemetry;
pub use oneiron_base::request_limits::DEFAULT_CALL_MODE_DEADLINE;
use oneiron_base::retrieval_quality::ConfidenceAdjustment;
use oneiron_base::retrieval_quality::RetrievalDegradation;
use oneiron_base::retrieval_quality::RetrievalQuality;
use serde::Deserialize;
use serde::Serialize;

/// Retrieval effort dial (S6). Deliberately distinct from `llm.rs`
/// `ReasoningEffort` (the LLM dial) and `context_pack.rs` `FieldProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Available vector, text, phonetic and temporal signals, then blend.
    Light,
    /// Light plus seed-specific search PPR.
    Medium,
    /// Medium plus two-hop expansion and top-30 reranking.
    High,
    /// Four-hop expansion and top-50 reranking.
    Xhigh,
    /// Ten-hop expansion, top-50 reranking and bitemporal search.
    Max,
}

impl Effort {
    /// Stable five-level wire vocabulary. Retired names are not aliases.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "light" => Some(Self::Light),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            "max" => Some(Self::Max),
            _ => None,
        }
    }

    /// Paid tiers require an explicit lease and reranker; never silent fallback.
    #[must_use]
    pub const fn requires_rerank(self) -> bool {
        matches!(self, Self::High | Self::Xhigh | Self::Max)
    }

    #[must_use]
    pub const fn graph_depth(self) -> u32 {
        match self {
            Self::Light => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Xhigh => 4,
            Self::Max => 10,
        }
    }

    #[must_use]
    pub const fn rerank_top_n(self) -> usize {
        match self {
            Self::Xhigh | Self::Max => 50,
            _ => 30,
        }
    }
}

/// Recall scoping (S5): world/facet narrowing and the kinds returned — unset
/// means the vault floor; the scope never widens beyond it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallScope {
    /// WORLD entity ref; scopes to that world plus base reality. Unset reads
    /// base plus the actor's active world (ARCH-0022), never every world.
    pub world_ref: Option<String>,
    /// Explicit All, Base or world/set selection; a non-base selection can decline base.
    #[serde(default)]
    pub worlds: Option<super::RecallWorlds>,
    /// Project audience ids. Empty requests add no narrowing to the credential.
    #[serde(default)]
    pub project_refs: Vec<String>,
    /// Conversation entity refs. Empty adds no narrowing; with `person_ref`,
    /// only conversations selected by both axes remain.
    #[serde(default)]
    pub conversation_refs: Vec<String>,
    /// PERSON entity ref; selects conversations where they authored at least
    /// one live MESSAGE, never conversations that merely mention them.
    pub person_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
    /// Registry kinds to return (`MESSAGE`, `CLAIM`, `PERSON`, ...). Unset
    /// returns every kind but the ones with no text of their own
    /// ([`CONTAINER_KINDS`]), so `limit` slots go to rows that say something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// Item provenance (S6, default-on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemoryProvenance {
    /// Claim source string, or `record` for structural source records.
    pub source: String,
    /// This revision plus superseded ancestors (32-hex ids). A TURN's also
    /// names each message its text is read from that the reader may read,
    /// so a live view of the turn follows a change to any of them.
    pub source_revision_ids: Vec<String>,
    /// Evidence TURN ids. Populated structurally for MESSAGE items; claim
    /// evidence stamping is the extraction pipeline's later responsibility.
    pub evidence_turn_ids: Vec<String>,
}

/// Scope honesty (S6): what the scope excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopeHonesty {
    /// Worlds holding surfaceable claims outside the requested scope.
    pub out_of_scope_worlds: Vec<String>,
    /// The census stopped at its scan cap or at the answer's deadline, so a
    /// world past it may be missing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub census_capped: bool,
}

pub fn is_false(value: &bool) -> bool {
    !*value
}

/// Retrieval accounting (S6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalMeta {
    #[serde(default)]
    pub quality: RetrievalQuality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradation: Vec<RetrievalDegradation>,
    #[serde(default)]
    pub confidence_adjustment: ConfidenceAdjustment,
    /// True when only sparse (lexical/graph) signals ran — no dense
    /// vector signal is available until the embedder lane lands.
    pub sparse: Option<bool>,
    /// Candidates considered by the retrieval pipeline.
    pub total_candidates: u64,
    /// CLAIM items in the returned pack.
    pub claims_returned: u64,
    /// Retained wire field. Always `None`: paid work never pretends to complete.
    pub deep_pending: Option<bool>,
    /// Requested stages skipped or cut at the explicit deadline: the pack
    /// holds what was ready when it came due. Also set when a device that
    /// syncs only what it opened answered without its home
    /// ([`MemoryPack::residence`]).
    #[serde(default)]
    pub partial: bool,
    /// Time phrases read from the query, in order. `used` ones narrowed the
    /// occurred-time window; `unresolved` and `future` ones were skipped and
    /// recall ran on its other signals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporal_hints: Vec<oneiron_contracts::temporal::TemporalHintReport>,
    /// What the rerank stage of a recall at high, xhigh or max did: the
    /// model whose scores ordered the top block, or why it was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerank: Option<RerankReport>,
    /// The request's `limit` was past the ceiling (1,000 rows) and was
    /// served at it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub limit_clamped: bool,
}

/// `vault.recall`'s inputs, spelled exactly as §HEAD-CONTRACT does.
///
/// Every field but `query` is optional and defaults to the contract's default,
/// so an omitting client and a spelling-everything client reach the same
/// engine call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallRequest {
    pub query: String,
    /// One of the five effort levels, or `call`: call mode for live calls,
    /// light effort under a hard deadline. Omitted means `medium`.
    #[serde(default)]
    pub effort: Option<crate::memory::recall::call_mode::RecallEffort>,
    #[serde(default)]
    pub scope: Option<crate::memory::recall::RecallScope>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub format: Option<String>,
    /// The token budget `format`'s rendering is cut to; 0 renders it uncut.
    /// Omitted, the window budget of `reader_agent_ref`'s memory profile,
    /// else 4,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<u64>,
    /// An agent definition the caller reads whose memory profile sizes the
    /// rendering when `token_budget` is omitted. It grants no read, and one
    /// the caller cannot read adds no budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_agent_ref: Option<String>,
    /// Unix seconds the query's time words resolve against: `yesterday` is
    /// the day before it. Omitted, they resolve against now.
    #[serde(default)]
    pub as_of: Option<u64>,
    /// A hard deadline, in milliseconds from when the request arrives,
    /// 1 to 60000: at it, recall answers with the best results ready, marked
    /// `partial`. Omitted, recall runs to the end, except call mode, which
    /// takes the vault's call-mode deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// A media query (OF-370): bytes the host embeds into one declared space
    /// through the `ai.embed` rung that space's id names, searched as that
    /// space's list beside the query's. A host that serves no such rung
    /// refuses the recall with `MODEL_UNAVAILABLE`; it never recalls without
    /// the media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<oneiron_contracts::code_run::vault_read::ContextPackMediaQuery>,
    /// The affect the query is asked in (OF-423), as the context pack takes
    /// it: emotion congruence ranks a candidate by how near its own valence,
    /// arousal and dominance sit. Omitted, recall ranks as before.
    #[serde(
        default,
        alias = "queryAffect",
        skip_serializing_if = "Option::is_none"
    )]
    pub query_affect: Option<QueryAffect>,
    /// Local diagnostics only. Capture stays opt-in at vault configuration;
    /// the request can add stage detail and the host's exact turn identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<RecallTelemetry>,
    /// The caller's retrieval filter (FIX 3977, `#t-filter`): it only
    /// narrows the vault's floor, and every stage of the recall meets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
    /// The caller's operation id (RESEARCH-0363 p5): 1 to 128 of
    /// `A-Z a-z 0-9 . _ : -`. The first recall under it keeps its items' ids
    /// and the revisions it served them at, never their text. The same
    /// request under it again rebuilds those items at those revisions under
    /// the caller's current read, and answers them only when they are the
    /// same; otherwise it refuses with `INVALID_STATE`, so an erase or a
    /// narrowed read never serves an old answer. It takes no `format` and no
    /// deadline. Omitted, recall runs as before.
    #[serde(
        default,
        alias = "operationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub operation_id: Option<String>,
}
pub mod call_mode;
pub mod home;
pub mod paid;
