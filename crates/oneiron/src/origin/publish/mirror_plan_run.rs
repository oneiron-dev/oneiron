//! One automatic run over a mirror's plans (FIX 6866 part 2): the mirror's
//! open plan settles first, and only a mirror with none freezes a new one.
//!
//! The caller holds the mirror's push hold for the whole run, so a plan
//! left claimed by a crash has no child alive when the run reads it. An open
//! plan's run releases those stale claims, reconciles every unproven ref
//! (`mirror_plan_reconcile`), sends the batches left (`mirror_plan_dispatch`)
//! and settles the plan once every ref needs nothing more. A new plan is
//! frozen (`mirror_plan`) and sent the same way. Every error here ends the
//! run before anything more goes out; the caller holds it and records why.

use super::mirror_plan::{MirrorRunScope, MirrorSelection};
use super::mirror_plan_dispatch::ref_outcomes;
use super::mirror_plan_reconcile::MirrorReconcile;
use super::mirror_plan_types::{MirrorBatchClaim, MirrorPushPlan, MirrorRefOutcome};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitOid, GitRefName};

/// The longest failure a run summary names.
const MIRROR_RUN_MAX_FAILURE_BYTES: usize = 512;

/// Where one plan stands after a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirrorPlanSummary {
    pub(crate) plan_id: EntityId,
    pub(crate) digest: String,
    /// Whether every ref needs nothing more; the plan is closed then.
    pub(crate) settled: bool,
    /// Whether every ref landed.
    pub(crate) landed: bool,
    /// Refs the plan pushes, and refs it deletes.
    pub(crate) refs: u64,
    pub(crate) deleted: u64,
    /// The `(ref, object)` vector, for the census and the pushed names.
    pub(crate) vector: Vec<(GitRefName, GitOid)>,
    /// Refs someone else moved, and refs the mirror refused twice.
    pub(crate) remote_moved: Vec<String>,
    pub(crate) refused: Vec<String>,
    /// The full-auto refs the plan held for checks.
    pub(crate) held: Vec<String>,
    /// Why the run did not land whole, bounded; `None` when it did.
    pub(crate) failure: Option<String>,
    /// How the run's reconcile went.
    pub(crate) reconcile: MirrorReconcile,
}

impl Vault {
    /// Runs the mirror's open plan as far as it goes now. `None` when the
    /// mirror has no open plan.
    pub(crate) fn continue_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
    ) -> Result<Option<MirrorPlanSummary>> {
        let (plan_id, plan) = {
            let txn = self.store.env.read_txn()?;
            let head = self.mirror_work_head_in_txn(&txn, scope.repo_id)?;
            let Some(plan_id) = head.open else {
                return Ok(None);
            };
            (
                plan_id,
                self.mirror_plan_in_txn(&txn, scope.repo_id, plan_id)?,
            )
        };
        // A plan an actor scrub dropped as undecodable can never send.
        let Some(plan) = plan else {
            self.forget_open_mirror_plan(scope.repo_id, plan_id)?;
            return Ok(None);
        };
        self.release_stale_mirror_claims(&plan)?;
        let reconcile = self.reconcile_mirror_plan(scope, &plan)?;
        self.drive_mirror_plan(scope, &plan, reconcile).map(Some)
    }

    /// Freezes a new plan for `selection` and sends it. `None` when the
    /// mirror row moved since the run read it, or another plan is open.
    pub(crate) fn start_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        selection: &MirrorSelection,
        requested_by: Option<EntityId>,
    ) -> Result<Option<MirrorPlanSummary>> {
        let Some(plan) = self.freeze_mirror_plan(scope, selection, requested_by)? else {
            return Ok(None);
        };
        self.drive_mirror_plan(scope, &plan, MirrorReconcile::Nothing)
            .map(Some)
    }

    /// The vector digest of the plan the mirror settled last, and whether
    /// every ref of it landed; `None` when it settled none.
    pub(crate) fn mirror_plan_settled_last(
        &self,
        repo_id: EntityId,
    ) -> Result<Option<(String, bool)>> {
        let txn = self.store.env.read_txn()?;
        let head = self.mirror_work_head_in_txn(&txn, repo_id)?;
        Ok(head.last.map(|last| (last.vector, last.landed)))
    }

    /// Sends what is left of `plan` and settles it when every ref needs
    /// nothing more.
    fn drive_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        reconcile: MirrorReconcile,
    ) -> Result<MirrorPlanSummary> {
        self.send_mirror_plan(scope, plan)?;
        let mut txn = self.store.env.write_txn()?;
        let batches = self.mirror_batches_in_txn(&txn, plan)?;
        let outcomes = ref_outcomes(plan, &batches);
        let summary = summarize(plan, &outcomes, reconcile)?;
        if summary.settled {
            self.close_mirror_plan_in_txn(&mut txn, plan, summary.landed)?;
            txn.commit()?;
        }
        Ok(summary)
    }
}

impl Vault {
    /// Closes an open plan whose row is gone (an actor scrub dropped it as
    /// undecodable): it can never send, so the mirror plans again.
    pub(super) fn forget_open_mirror_plan(
        &self,
        repo_id: EntityId,
        plan_id: EntityId,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut head = self.mirror_work_head_in_txn(&txn, repo_id)?;
        if head.open != Some(plan_id) || self.mirror_plan_in_txn(&txn, repo_id, plan_id)?.is_some()
        {
            return Ok(());
        }
        head.open = None;
        head.unread = 0;
        self.put_mirror_work_head_in_txn(&mut txn, repo_id, &head)?;
        txn.commit()?;
        Ok(())
    }

    /// Pauses every batch of a mirror's open plan not yet claimed, in the
    /// transaction that changed the mirror's strategy, destination or row
    /// (FIX 6866 part 2, call 1). A claimed batch is left to its child and
    /// its reconcile. Everything is read before anything is written.
    pub(crate) fn pause_origin_mirror_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
    ) -> Result<()> {
        let head = self.mirror_work_head_in_txn(txn, repo_id)?;
        let Some(plan_id) = head.open else {
            return Ok(());
        };
        let Some(plan) = self.mirror_plan_in_txn(txn, repo_id, plan_id)? else {
            return Ok(());
        };
        let mut batches = self.mirror_batches_in_txn(txn, &plan)?;
        for (index, progress) in (0_u32..).zip(batches.iter_mut()) {
            if progress.claim != MirrorBatchClaim::Pending {
                continue;
            }
            progress.claim = MirrorBatchClaim::Paused;
            for outcome in &mut progress.outcomes {
                if *outcome == MirrorRefOutcome::Pending {
                    *outcome = MirrorRefOutcome::Paused;
                }
            }
            self.put_mirror_batch_in_txn(txn, &plan, index, progress)?;
        }
        Ok(())
    }

    /// Whether a mirror has an open plan to settle.
    pub(crate) fn origin_mirror_work_open(&self, repo_id: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self.mirror_work_head_in_txn(&txn, repo_id)?.open.is_some())
    }
}

/// A plan's summary from each ref's outcome.
fn summarize(
    plan: &MirrorPushPlan,
    outcomes: &[MirrorRefOutcome],
    reconcile: MirrorReconcile,
) -> Result<MirrorPlanSummary> {
    let mut vector = Vec::new();
    let (mut deleted, mut unproven, mut paused) = (0_u64, 0_u64, 0_u64);
    let (mut remote_moved, mut refused) = (Vec::new(), Vec::new());
    for (plan_ref, outcome) in plan.refs.iter().zip(outcomes) {
        match &plan_ref.new {
            Some(new) => vector.push((
                GitRefName::parse_full(plan_ref.ref_name.clone())?,
                GitOid::parse_hex(new.clone())?,
            )),
            None => deleted = deleted.saturating_add(1),
        }
        match outcome {
            MirrorRefOutcome::RemoteMoved => remote_moved.push(plan_ref.ref_name.clone()),
            MirrorRefOutcome::Refused => refused.push(plan_ref.ref_name.clone()),
            MirrorRefOutcome::Paused => paused = paused.saturating_add(1),
            outcome if !outcome.settled() => unproven = unproven.saturating_add(1),
            _ => {}
        }
    }
    let settled = outcomes.iter().all(|outcome| outcome.settled());
    let landed = outcomes.iter().all(|outcome| outcome.landed());
    let failure = (!landed).then(|| {
        let mut parts = Vec::new();
        if unproven > 0 {
            parts.push(format!(
                "mirror_plan_unproven: {unproven} refs await a reconcile read"
            ));
        }
        if !remote_moved.is_empty() {
            parts.push(format!("remote_moved: {}", remote_moved.join(",")));
        }
        if !refused.is_empty() {
            parts.push(format!("refused: {}", refused.join(",")));
        }
        if paused > 0 {
            parts.push(format!("paused: {paused} refs never sent"));
        }
        bounded_failure(parts.join("; "))
    });
    Ok(MirrorPlanSummary {
        plan_id: plan.plan_id,
        digest: plan.digest.clone(),
        settled,
        landed,
        refs: u64::try_from(vector.len()).unwrap_or(u64::MAX),
        deleted,
        vector,
        remote_moved,
        refused,
        held: plan
            .pending_checks
            .iter()
            .map(|held| held.ref_name.clone())
            .collect(),
        failure,
        reconcile,
    })
}

/// A failure cut to [`MIRROR_RUN_MAX_FAILURE_BYTES`] on a character
/// boundary.
fn bounded_failure(mut text: String) -> String {
    let mut cut = text.len().min(MIRROR_RUN_MAX_FAILURE_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}
