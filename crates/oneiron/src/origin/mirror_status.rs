//! What every automatic mirror push run shows on its mirror row, and the
//! hold of a run that failed before egress (FIX 6866 part 2; Engine 10-21
//! 07:5x, CALLS "FIX 6866 review failure = hold").
//!
//! A `schedule` or `full_auto` run whose review or plan could not be read or
//! stored stops before any ref goes out. It is never dropped and never sent
//! unreviewed: the mirror row shows `review_unavailable` with its typed
//! cause and when it was last seen, a typed WARN names it, the run records
//! its failure, and the next interval (`full_auto`: the next wake or tick)
//! reviews again from scratch on that run's refs. A status that cannot be
//! written warns: it never fails the run, a local effect or a config read.

use super::mirror::TARGETS;
use super::mirror_auto::{
    ORIGIN_MIRROR_REVIEW_UNAVAILABLE, OriginMirrorAutomation, OriginMirrorHold,
    OriginMirrorHoldCause,
};
use super::mirror_run::WholeRefsRun;
use super::publish::{MirrorPlanSummary, MirrorReconcile, MirrorRunScope};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The hold a run that failed with `error` shows, counting `prior`.
pub(super) fn hold_of(
    error: &Error,
    prior: Option<&OriginMirrorHold>,
    now: u64,
) -> OriginMirrorHold {
    OriginMirrorHold {
        cause: OriginMirrorHoldCause::of(error),
        error_kind: format!("{:?}", error.kind()),
        last_seen: now,
        times: prior.map_or(1, |hold| hold.times.saturating_add(1)),
    }
}

impl Vault {
    /// Rewrites the mirror row's automation status through `change`, while
    /// the row is still the generation the run read. A write that fails
    /// warns; it never fails the run, a local effect or a config read.
    pub(super) fn note_mirror_automation(
        &self,
        repo_id: EntityId,
        generation: Option<EntityId>,
        change: impl FnOnce(&mut OriginMirrorAutomation),
    ) {
        let written = (|| -> Result<()> {
            let mut txn = self.store.env.write_txn()?;
            let Some(mut row) = TARGETS.get(&self.store, &txn, &repo_id)? else {
                return Ok(());
            };
            if row.target_generation != generation {
                return Ok(());
            }
            let mut status = row.automation.clone().unwrap_or_default();
            change(&mut status);
            if row.automation.as_ref() == Some(&status) {
                return Ok(());
            }
            row.automation = Some(status);
            TARGETS.put(&self.store, &mut txn, &repo_id, &row)?;
            txn.commit()?;
            Ok(())
        })();
        if let Err(error) = written {
            tracing::warn!(
                code = "origin_mirror_status_not_recorded",
                repo_id = %repo_id.to_hex(),
                kind = ?error.kind(),
                "an automatic mirror run's status was not recorded; the next run writes it again"
            );
        }
    }

    /// What a run that reached its plan reports: the counts, names and
    /// census refs when every ref landed, else its failure, with the
    /// plan's state on the mirror's status.
    pub(super) fn finish_mirror_run(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        summary: &MirrorPlanSummary,
    ) -> Result<WholeRefsRun> {
        let now = self.now_recorded_at();
        let generation = scope.target.target_generation;
        if let MirrorReconcile::Unreadable { cause, unread } = &summary.reconcile {
            tracing::warn!(
                code = "reconcile_unavailable",
                repo_id = %scope.repo_id.to_hex(),
                unread,
                cause = %cause,
                "an automatic mirror plan's reconcile read failed; the plan stays frozen"
            );
        }
        self.note_mirror_automation(scope.repo_id, generation, |status| {
            status.plan_id = Some(summary.plan_id);
            status.plan_digest = Some(summary.digest.clone());
            status.plan_settled = summary.settled;
            status.review_unavailable = None;
            status.reconcile_unavailable = match &summary.reconcile {
                MirrorReconcile::Unreadable { unread, .. } => Some(OriginMirrorHold {
                    cause: OriginMirrorHoldCause::RemoteRead,
                    error_kind: "remote_read".to_owned(),
                    last_seen: now,
                    times: *unread,
                }),
                MirrorReconcile::Nothing | MirrorReconcile::Read => None,
            };
            if summary.settled {
                status.remote_moved.clone_from(&summary.remote_moved);
                status.refused.clone_from(&summary.refused);
            }
        });
        if !summary.landed {
            return Err(Error::Refused(summary.failure.clone().unwrap_or_else(
                || "mirror_plan_unsettled: the plan has refs left to settle".to_owned(),
            )));
        }
        let mut names: Vec<String> = summary
            .vector
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        // A held full-auto ref the mirror took before keeps its name, so no
        // run deletes it while it waits for checks.
        let kept: Vec<String> = summary
            .held
            .iter()
            .filter(|held| scope.target.pushed.contains(held) && !names.contains(held))
            .cloned()
            .collect();
        names.extend(kept);
        Ok(WholeRefsRun {
            refs: summary.refs,
            deleted: summary.deleted,
            names,
            census: summary.vector.clone(),
        })
    }

    /// Holds a run that failed before egress: a typed WARN, the
    /// `review_unavailable` status, and the error the run records.
    pub(super) fn hold_mirror_run(&self, scope: &MirrorRunScope<'_, '_>, error: &Error) -> Error {
        let now = self.now_recorded_at();
        let mut cause = None;
        self.note_mirror_automation(scope.repo_id, scope.target.target_generation, |status| {
            let hold = hold_of(error, status.review_unavailable.as_ref(), now);
            cause = Some(hold.cause);
            status.review_unavailable = Some(hold);
        });
        tracing::warn!(
            code = ORIGIN_MIRROR_REVIEW_UNAVAILABLE,
            repo_id = %scope.repo_id.to_hex(),
            kind = ?error.kind(),
            "an automatic mirror run held before egress: its review or plan was unreadable"
        );
        Error::Refused(format!(
            "{ORIGIN_MIRROR_REVIEW_UNAVAILABLE}: the run's review or plan could not be read or \
             stored ({:?}, {:?}); the next run reviews again",
            cause.unwrap_or_else(|| OriginMirrorHoldCause::of(error)),
            error.kind()
        ))
    }
}

impl Vault {
    /// Pauses the mirror's unsent automatic work in the transaction that
    /// moves its strategy or destination, or clears it (FIX 6866 call 1): a
    /// batch not yet claimed is never sent, and a running child settles
    /// first. A read that fails here warns, never fails the owner's write:
    /// each batch's claim fences the same change.
    pub(super) fn pause_mirror_work_on_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
    ) {
        if let Err(error) = self.pause_origin_mirror_work_in_txn(txn, repo_id) {
            tracing::warn!(
                code = "origin_mirror_work_not_paused",
                repo_id = %repo_id.to_hex(),
                kind = ?error.kind(),
                "a mirror's unsent automatic work was not paused here; its next claim pauses it"
            );
        }
    }
}
