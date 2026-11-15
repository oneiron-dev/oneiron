//! Moved from `crates/oneiron/src/context_pack/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::retrieval_signal::Signal;
pub use oneiron_store::serialize::context_entity::ContextEntity;
pub use oneiron_store::serialize::pack_accounting::ContextPackRetrievalBudget;
pub use oneiron_store::serialize::pack_accounting::PackItemAccounting;
pub use oneiron_store::serialize::pack_accounting::PackItemAccountingReason;
pub use oneiron_store::serialize::pack_accounting::PackItemTokenStats;
pub use oneiron_store::serialize::pack_accounting::PackSectionTokenStats;
pub use oneiron_store::serialize::pack_accounting::PackTokenStats;
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
    /// What the pack did with the working set its caller seeded
    /// (`oneiron::context_pack::ContextPackBuilder::working_set`); all zero
    /// when unseeded.
    pub working_set: PackWorkingSetStats,
}

/// What a pack did with the working set its caller seeded
/// (`oneiron::context_pack::ContextPackBuilder::working_set`). Every field is
/// zero for a pack with no working set.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PackWorkingSetStats {
    /// Refs the caller named, after duplicates were removed.
    pub asked: usize,
    /// The working-set rows the pack serves, in working-set order: the ones
    /// its rows still hold after its last cut (a response limit, a scoped
    /// read's filter, a serialized budget; a row inside a serialized pack's
    /// L2 base prefix is held there). A superseded CLAIM ref is served as its
    /// live successor.
    pub served: Vec<EntityId>,
    /// Refs the assembled pack does not serve: dead, hidden from the reader,
    /// erased, quarantined, clamped, unusable as a row, outside the pack's
    /// worlds, types or query, or cut by the world share. One count for every
    /// reason. A later cut counts where that cut counts its rows.
    pub dropped: usize,
    /// Working-set rows a serialized pack cut because the working set's
    /// rows passed half of the pack's token budget.
    pub over_cap: usize,
    /// Working-set rows the ranked fill also found. Each is served once, as
    /// a working-set row.
    pub overlap: usize,
}

impl PackWorkingSetStats {
    /// Whether the pack was seeded at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asked == 0
    }

    /// Keeps in [`Self::served`] only the rows `held` says the pack still
    /// holds, in working-set order. Each cut that removes rows calls it.
    pub fn settle(&mut self, held: impl Fn(&EntityId) -> bool) {
        self.served.retain(|id| held(id));
    }
}
