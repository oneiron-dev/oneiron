//! Public value types of the context pack: the pack itself, its entities, its
//! stats, and its budget/allocation knobs.

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

pub use crate::serialize::pack_format::{FieldProfile, PackFormat};

pub use crate::serialize::context_entity::ContextEntity;

#[doc(hidden)]
pub use oneiron_records::context_pack::types::PackStats;

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
