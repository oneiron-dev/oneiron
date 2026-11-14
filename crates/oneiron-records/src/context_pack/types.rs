//! Moved from `crates/oneiron/src/context_pack/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::retrieval_signal::Signal;
pub use oneiron_store::serialize::context_entity::ContextEntity;
pub use oneiron_store::serialize::pack_accounting::ContextPackRetrievalBudget;
pub use oneiron_store::serialize::pack_accounting::PackItemAccounting;
pub use oneiron_store::serialize::pack_accounting::PackItemAccountingReason;
pub use oneiron_store::serialize::pack_accounting::PackItemTokenStats;
pub use oneiron_store::serialize::pack_accounting::PackSectionTokenStats;
pub use oneiron_store::serialize::pack_accounting::PackTokenStats;
pub(crate) use oneiron_store::serialize::pack_accounting::PackWorldShare;
pub use oneiron_store::serialize::pack_accounting::TokenAllocation;
pub use oneiron_store::serialize::pack_format::FieldProfile;
pub use oneiron_store::serialize::pack_format::PackFormat;

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
