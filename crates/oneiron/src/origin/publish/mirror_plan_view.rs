//! The read of one automatic mirror push plan (FIX 7175;
//! `vault.code.origin.mirror.plan`): what a `schedule` or `full_auto` run
//! froze, where each of its refs and batches stands, and one page of its
//! review, as `ORIGIN_MIRROR_WORK` keeps them. The mirror row's automation
//! status names only the newest plan; this names any plan the mirror keeps.

use serde::{Deserialize, Serialize};

use super::mirror_plan_dispatch::ref_outcomes;
use super::mirror_plan_types::{MirrorBatchClaim, MirrorObservedTip, MirrorRefOutcome};
use super::types::{OriginPublishDestination, OriginPublishReview, OriginPublishReviewItem};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::mirror_auto::OriginMirrorPendingCheck;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;

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
}

impl Vault {
    /// One automatic plan of `input.repo`'s mirror (module docs). A plan the
    /// mirror no longer keeps is not found; a page past the review's last is
    /// refused.
    pub fn origin_mirror_plan(
        &self,
        input: OriginMirrorPlanRequest,
    ) -> Result<OriginMirrorPlanView> {
        let repo_id = self.served_mirror_repo_id(&input.repo)?;
        let txn = self.store.env.read_txn()?;
        let head = self.mirror_work_head_in_txn(&txn, repo_id)?;
        let wanted = input
            .plan_id
            .or(head.open)
            .or_else(|| head.last.as_ref().map(|last| last.plan_id));
        let plan = match wanted {
            None => None,
            Some(plan_id) => {
                let plan = self
                    .mirror_plan_in_txn(&txn, repo_id, plan_id)?
                    .ok_or(Error::EntityNotFound)?;
                let items = if plan.pages == 0 && input.page == 0 {
                    Vec::new()
                } else if input.page < plan.pages {
                    self.mirror_plan_page_in_txn(&txn, &plan, input.page)?
                        .ok_or(Error::CorruptedIndex("origin mirror plan review page"))?
                        .items
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "the plan's review has {} pages; page {} is past its last",
                        plan.pages, input.page
                    )));
                };
                let batches = self.mirror_batches_in_txn(&txn, &plan)?;
                let outcomes = ref_outcomes(&plan, &batches);
                Some(OriginMirrorPlanRecord {
                    plan_id: plan.plan_id,
                    settled: head.open != Some(plan.plan_id),
                    refs: plan
                        .refs
                        .iter()
                        .zip(outcomes)
                        .map(|(plan_ref, outcome)| OriginMirrorPlanRefView {
                            ref_name: plan_ref.ref_name.clone(),
                            new: plan_ref.new.clone(),
                            observed: plan_ref.observed.clone(),
                            review: plan_ref.review.clone(),
                            first_page: plan_ref.first_page,
                            batch: plan_ref.batch,
                            outcome,
                        })
                        .collect(),
                    batches: batches
                        .into_iter()
                        .map(|progress| OriginMirrorPlanBatchView {
                            claim: progress.claim,
                            refs: progress.refs,
                            detail: progress.detail,
                        })
                        .collect(),
                    pending_checks: plan
                        .pending_checks
                        .iter()
                        .map(|held| OriginMirrorPendingCheck {
                            ref_name: held.ref_name.clone(),
                            head: held.head.clone(),
                            sent: held.sent.clone(),
                        })
                        .collect(),
                    destination: plan.destination,
                    strategy: plan.strategy,
                    strategy_revision: plan.strategy_revision,
                    requested_by: plan.requested_by,
                    digest: plan.digest,
                    vector: plan.vector,
                    created_at: plan.created_at,
                    page: input.page,
                    pages: plan.pages,
                    items,
                })
            }
        };
        Ok(OriginMirrorPlanView {
            repo: input.repo,
            open: head.open,
            kept: head.kept,
            plan,
        })
    }
}
