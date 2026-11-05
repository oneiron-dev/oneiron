//! Core half of `origin::publish::mirror_plan_types`: its store-layer items live in `oneiron_store::origin::publish::mirror_plan_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::publish::mirror_plan_types::*;

use super::types::{OriginPublishDestination, OriginPublishReview, OriginPublishReviewPage};
use crate::entity_id::EntityId;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use serde::{Deserialize, Serialize};

/// One ref of a frozen plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorPlanRef {
    /// The full ref at the mirror.
    pub(crate) ref_name: String,
    /// The object it is pushed to, 40 lower hex; `None` deletes it.
    pub(crate) new: Option<String>,
    pub(crate) observed: MirrorObservedTip,
    /// Its review section; `None` for a deletion, which exposes nothing.
    pub(crate) review: Option<OriginPublishReview>,
    /// The plan page its section starts at.
    pub(crate) first_page: u64,
    /// The batch it goes in; `None` when it needs no push (a deletion the
    /// mirror already lacks, a covered full-auto ref).
    pub(crate) batch: Option<u32>,
}

/// One frozen plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorPushPlan {
    pub(crate) plan_id: EntityId,
    /// The served name, and the object-store-derived repository id.
    pub(crate) repo: String,
    pub(crate) repo_id: EntityId,
    pub(crate) destination: OriginPublishDestination,
    pub(crate) strategy: OriginMirrorSyncStrategy,
    pub(crate) strategy_revision: u64,
    /// The owner whose push-now froze it; `None` for a cadence or an event,
    /// and once the actor is erased.
    pub(crate) requested_by: Option<EntityId>,
    /// Updates in published order, then deletions.
    pub(crate) refs: Vec<MirrorPlanRef>,
    pub(crate) batches: u32,
    pub(crate) pending_checks: Vec<MirrorPendingHead>,
    /// BLAKE3, 64 lower hex, over everything above and each section digest.
    pub(crate) digest: String,
    /// The vector's own digest, which a full-auto mirror compares its next
    /// selection with.
    pub(crate) vector: String,
    pub(crate) pages: u64,
    pub(crate) created_at: u64,
}

/// One row of the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum MirrorWorkRow {
    Head(MirrorWorkHead),
    Plan(Box<MirrorPushPlan>),
    Page(OriginPublishReviewPage),
    Batch(MirrorBatchProgress),
}
