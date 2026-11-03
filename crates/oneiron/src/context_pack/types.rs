//! Public value types of the context pack: the pack itself, its entities, its
//! stats, and its budget/allocation knobs.

use crate::pipeline::Signal;
use crate::retrieval_quality::RetrievalQualityReport;

use super::empty_pack::EmptyContext;

pub const DEFAULT_MAX_NEIGHBORS: usize = 50;
/// The engine-default context-window token budget — the value an absent
/// `AgentDefinition.memory_profile` reproduces (RT-05, ONE-1687).
///
/// RENAMED, never revalued: an agent with no profile assembles byte-for-byte
/// the pack it assembled before the lift. The value reaches consumers through
/// [`super::ContextPackBuilder::effective_token_budget`] on a default builder
/// rather than a second read of this constant, so the budget has ONE
/// authority. It is also the fallback when no model window is known at call
/// time (below), so a pack whose call site names no model assembles exactly
/// as it did before the window-relative default existed.
pub(super) const DEFAULT_WINDOW_TOKEN_BUDGET: usize = 4000;
/// The engine-default share of the active model's context window a pack
/// with no explicit or profile budget may fill (ARCH-0004 #budget-unit:
/// the default unit is `{ contextFraction }`, resolved to tokens at call
/// time). Canon tunes the value on BEAM and pins no number; this is the
/// one place that tuning lands. The fraction applies to the model's full
/// catalog window; the rest of the window stays the prompt's and the
/// answer's.
pub(super) const DEFAULT_CONTEXT_FRACTION: f32 = 0.1;
pub const DEFAULT_MAX_FIELD_CHARS: usize = 500;
pub const MAX_EDGE_HOP: u32 = 5;
pub const MAX_CONTEXT_NEIGHBORS: usize = 1000;

/// Default share of the claim budget that non-base (fictional / dream) worlds
/// may occupy in an `All`-scope pack — fiction takes at most half, so it can
/// never crowd base reality out (ARCH-0004 / ARCH-0022).
pub(super) const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;

pub use crate::serialize::pack_format::{FieldProfile, PackFormat};

pub use crate::serialize::context_entity::ContextEntity;

/// Stats about the context pack query.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
    /// Candidates counted for lexical disagreement because they had vector
    /// similarity above the cosine-ghost threshold and no BM25 text channel
    /// presence.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records silently excluded by the D19 read-path status gate
    /// (ARCH-0003: surface only `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false`) or by the fail-closed type-0 body decode, across
    /// the pipeline stage and pack hydration (results + neighbors). A claim
    /// suppressed in both stages counts once per stage.
    pub claims_suppressed: usize,
    /// Token accounting populated by serialization/projection paths.
    ///
    /// Raw `ContextPackBuilder::run()` results are not serialized and leave
    /// this as `PackTokenStats::default()`. Use serialized/projection builder
    /// paths when exact output-token accounting is required.
    pub tokens: PackTokenStats,
    pub items_truncated: PackItemAccounting,
    pub items_dropped: PackItemAccounting,
    /// Critical claims exceeded an item, section, or serialized allotment.
    pub critical_over_budget: bool,
    /// Critical claims eligible before budget truncation (not suppressed claims).
    pub critical_count: usize,
    /// Assembly stopped optional work at the answer deadline (retrieval stages or L2/edge/hydration).
    pub deadline_exceeded: bool,
}

pub(crate) use crate::serialize::pack_accounting::{PackCriticalAccounting, PackWorldShare};
pub use crate::serialize::pack_accounting::{
    PackItemAccounting, PackItemAccountingReason, PackItemTokenStats, PackSectionTokenStats,
    PackTokenStats,
};

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    /// Turn-local discovery, separately budgeted from memory rows.
    pub capabilities: Vec<crate::context_board::CapabilityHit>,
    /// Cached, score-free subject evidence. Results and neighbors are its read-time delta.
    pub l2_base: Option<super::L2BaseSummary>,
    /// Channel execution health, retained even when no entities surface.
    pub retrieval_quality: RetrievalQualityReport,
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    /// Index-only handles to the instruction files on the ancestor paths of
    /// the code units among results and neighbors, each listed once.
    pub instruction_files: Vec<crate::codebase::CodeInstructionHandle>,
    pub stats: PackStats,
    pub empty: Option<EmptyContext>,
}

pub use crate::serialize::pack_accounting::{ContextPackRetrievalBudget, TokenAllocation};
