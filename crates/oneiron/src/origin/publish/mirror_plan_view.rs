//! The read of one automatic mirror push plan (FIX 7175;
//! `vault.code.origin.mirror.plan`): what a `schedule` or `full_auto` run
//! froze, where each of its refs and batches stands, and one page of its
//! review, as `ORIGIN_MIRROR_WORK` keeps them. The mirror row's automation
//! status names only the newest plan; this names any plan the mirror keeps.

use super::mirror_plan_dispatch::ref_outcomes;
use crate::Vault;
use crate::error::{Error, Result};
use crate::origin::mirror_auto::OriginMirrorPendingCheck;

#[doc(hidden)]
pub use oneiron_verb_wire::origin::publish::mirror_plan_view::{
    OriginMirrorPlanBatchView, OriginMirrorPlanRecord, OriginMirrorPlanRefView,
    OriginMirrorPlanRequest, OriginMirrorPlanView,
};

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
                            broker_isolation: progress.broker_isolation,
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
