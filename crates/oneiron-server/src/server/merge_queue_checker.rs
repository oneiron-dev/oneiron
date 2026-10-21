//! The standalone merge queue checker drain (FIX 6868). Each lifecycle
//! tick, the first at once, runs the owner-requested queue checks
//! ([`oneiron::Vault::pending_queue_checks`]) on a blocking thread, off the
//! request path and with no model seat, in plain and managed serve alike.
//! It shares the owner work drain's custody: the host's write gate admits
//! each unit and is held through its dispatch, result write and teardown;
//! a managed freeze admits none; the host's stop ends the running check as
//! held and lets its result commit before the pass joins.
//!
//! A pass starts by queueing again any check an executor left running: a
//! pass never starts while another runs. One repository runs at most
//! `[merge_queue].queue_check_concurrency` checks at once; the next waits.
//! Log lines carry counts and an error's kind, never a row's text.

mod executor;
mod tree;

use std::sync::Arc;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;

/// The lease owner a checker attempt is claimed under.
const QUEUE_CHECK_LEASE_OWNER: &str = "merge_queue_checker";

impl SyncServer {
    /// Starts one checker pass on a task of its own, held for the host's
    /// stop, unless the last pass is still running, the host is stopping,
    /// or the host's gate refused the tick.
    pub(super) async fn start_merge_queue_checker(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await
        {
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await;
            return;
        };
        let server = Arc::clone(self);
        let admit = Arc::clone(admit);
        let run = tokio::spawn(async move {
            let drain = Arc::clone(&server);
            match tokio::task::spawn_blocking(move || drain.drain_queue_checks(admission, &admit))
                .await
            {
                Ok(Ok(ran)) => {
                    if ran > 0 {
                        tracing::info!(ran, "queue checks ran");
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "queue checker pass failed");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "queue checker task failed");
                }
            }
            server
                .end_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await;
        });
        self.housekeeping_passes.hold(run);
    }

    /// One pass: every queued check this host may claim, one at a time,
    /// each under an admission of its own. A check its repository's active
    /// one holds back waits for a later pass.
    fn drain_queue_checks(
        &self,
        first: Box<dyn Send>,
        admit: &HousekeepingAdmission,
    ) -> oneiron::Result<usize> {
        let vault = self.vault();
        let requeued = vault.requeue_interrupted_queue_checks()?;
        if requeued > 0 {
            tracing::info!(requeued, "interrupted queue checks queued again");
        }
        let config = self.config.merge_queue.clone().unwrap_or_default();
        let concurrency = config.queue_check_concurrency();
        let mut admission = Some(first);
        let mut ran = 0_usize;
        for key in vault.pending_queue_checks()? {
            if self.housekeeping_passes.stopping() {
                break;
            }
            let Some(held) = admission.take().or_else(|| admit()) else {
                break;
            };
            let Some(work) = vault.claim_queue_check(&key, QUEUE_CHECK_LEASE_OWNER, concurrency)?
            else {
                admission = Some(held);
                continue;
            };
            let mut host = executor::QueueCheckExecutor::new(config.clone());
            let stop = || self.housekeeping_passes.stopping();
            match vault.run_queue_check(&work, &mut host, &stop) {
                Ok(_) => ran += 1,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "queue check did not settle");
                }
            }
            drop(held);
        }
        Ok(ran)
    }
}
