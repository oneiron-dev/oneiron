//! Moved from `crates/oneiron/src/origin/publish/mirror_plan_view.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::origin::mirror_auto::OriginMirrorPendingCheck;
use crate::origin::publish::types::OriginPublishDestination;
use crate::origin::publish::types::OriginPublishReview;
use crate::origin::publish::types::OriginPublishReviewItem;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BrokerIsolation;
use oneiron_store::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron_store::origin::publish::mirror_plan_types::MirrorBatchClaim;
use oneiron_store::origin::publish::mirror_plan_types::MirrorObservedTip;
use oneiron_store::origin::publish::mirror_plan_types::MirrorRefOutcome;
use serde::Deserialize;
use serde::Serialize;

/// Reads one automatic plan of a served repository's mirror.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorPlanRequest {
    pub repo: String,
    /// The plan; absent: the mirror's open plan, else the one it settled
    /// last.
    #[serde(default)]
    pub plan_id: Option<EntityId>,
    /// The review page, from 0.
    #[serde(default)]
    pub page: u64,
}

/// The mirror's plans, and the one read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPlanView {
    pub repo: String,
    /// The mirror's open plan, if any.
    pub open: Option<EntityId>,
    /// The settled plans the mirror keeps, oldest first.
    pub kept: Vec<EntityId>,
    /// The plan read; `None` when the mirror has none.
    pub plan: Option<OriginMirrorPlanRecord>,
}

/// One frozen plan and where it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPlanRecord {
    pub plan_id: EntityId,
    pub destination: OriginPublishDestination,
    pub strategy: OriginMirrorSyncStrategy,
    pub strategy_revision: u64,
    /// The owner whose push-now froze it; `None` for a cadence or an event,
    /// and once the actor is erased.
    pub requested_by: Option<EntityId>,
    /// BLAKE3, 64 lower hex, over the whole plan.
    pub digest: String,
    /// The digest of its `(ref, object)` vector and deletions.
    pub vector: String,
    pub created_at: u64,
    /// Whether it is settled: no longer the mirror's open plan.
    pub settled: bool,
    /// Updates in published order, then deletions, each where it stands.
    pub refs: Vec<OriginMirrorPlanRefView>,
    /// Its batches in order.
    pub batches: Vec<OriginMirrorPlanBatchView>,
    /// Full-auto heads it held back for want of green evidence.
    pub pending_checks: Vec<OriginMirrorPendingCheck>,
    /// One page of its review, from 0, of `pages`.
    pub page: u64,
    pub pages: u64,
    pub items: Vec<OriginPublishReviewItem>,
}

/// One ref of a plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPlanRefView {
    /// The full ref at the mirror.
    pub ref_name: String,
    /// The object it is pushed to, 40 lower hex; `None` deletes it.
    pub new: Option<String>,
    /// What the plan's authenticated read saw at the mirror.
    pub observed: MirrorObservedTip,
    /// Its review section; `None` for a deletion.
    pub review: Option<OriginPublishReview>,
    /// The review page its section starts at.
    pub first_page: u64,
    /// The batch it goes in; `None` when it needs no push.
    pub batch: Option<u32>,
    pub outcome: MirrorRefOutcome,
}

/// One batch of a plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPlanBatchView {
    pub claim: MirrorBatchClaim,
    /// Its refs, as indexes into the plan's refs.
    pub refs: Vec<u32>,
    /// The redacted cause of its last child that did not succeed.
    pub detail: Option<String>,
    /// How the credential broker the last push of its refs went through is
    /// kept apart from the daemon (ARCH-0069 `#broker-isolation`; FIX
    /// 19083): `same_user` shows the unproven badge. `None` when no broker
    /// carried one: an embedded vault's direct push, or one that never
    /// reached it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_isolation: Option<BrokerIsolation>,
}
