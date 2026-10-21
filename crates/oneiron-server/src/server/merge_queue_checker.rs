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
//!
//! The same drain drives every enrolled queue (G2 PR2): before it runs
//! checks it takes each queue's next steps (`MergeQueue::pending_work`,
//! `drive_one`), each a unit under an admission of its own, then runs the
//! checks those steps asked for, and repeats until nothing moves. A step is
//! taken at most once a pass. A committed queue write wakes this drain
//! alone ([`SyncServer::wake_merge_queue_checker`]); only the lifecycle
//! tick asks a held check or landing again.

mod executor;
mod received;
mod tree;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::merge_queue::{QueueDrivePass, QueueWork};

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;

/// The lease owner a checker attempt is claimed under.
const QUEUE_CHECK_LEASE_OWNER: &str = "merge_queue_checker";

/// Whether a checker pass ran in this process yet: the first one asks
/// again for a check that needed host configuration.
static QUEUE_DRIVER_STARTED: AtomicBool = AtomicBool::new(false);

impl SyncServer {
    /// Starts one checker pass on a task of its own, held for the host's
    /// stop, unless the last pass is still running, the host is stopping,
    /// or the host's gate refused the tick.
    pub(super) async fn start_merge_queue_checker(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        self.start_queue_checker_pass(admit, true).await;
    }

    /// The same pass, woken by a committed queue write rather than the
    /// tick: it never asks a held check or landing again.
    pub(super) async fn wake_merge_queue_checker(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        self.start_queue_checker_pass(admit, false).await;
    }

    async fn start_queue_checker_pass(self: &Arc<Self>, admit: &HousekeepingAdmission, tick: bool) {
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
            match tokio::task::spawn_blocking(move || {
                drain.drain_queue_checks(admission, &admit, tick)
            })
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

    /// One pass: the enrolled queues' next steps, then every queued check
    /// this host may claim, one at a time, each under an admission of its
    /// own, again until nothing moves. A check its repository's active one
    /// holds back waits for a later pass.
    fn drain_queue_checks(
        &self,
        first: Box<dyn Send>,
        admit: &HousekeepingAdmission,
        tick: bool,
    ) -> oneiron::Result<usize> {
        let vault = self.vault();
        let requeued = vault.requeue_interrupted_queue_checks()?;
        if requeued > 0 {
            tracing::info!(requeued, "interrupted queue checks queued again");
        }
        let config = self.config.merge_queue.clone().unwrap_or_default();
        let concurrency = config.queue_check_concurrency();
        let pass = QueueDrivePass {
            tick,
            first: !QUEUE_DRIVER_STARTED.swap(true, Ordering::SeqCst),
        };
        let mut admission = Some(first);
        let mut driven = Vec::new();
        let mut intaken = Vec::new();
        let mut ran = 0_usize;
        loop {
            let Some(moved) = self.drive_queues(&mut admission, admit, pass, &mut driven)? else {
                break;
            };
            // Accepted pushes become Proposed bundles after the queues'
            // own steps, before their checks, once a drain (G4 PR2).
            let Some(proposed) =
                self.intake_received_candidates(&mut admission, admit, &mut intaken)?
            else {
                break;
            };
            let moved = moved + proposed;
            let mut checked = 0_usize;
            for key in vault.pending_queue_checks()? {
                if self.housekeeping_passes.stopping() {
                    return Ok(ran + checked);
                }
                let Some(held) = admission.take().or_else(|| admit()) else {
                    return Ok(ran + checked);
                };
                let Some(work) =
                    vault.claim_queue_check(&key, QUEUE_CHECK_LEASE_OWNER, concurrency)?
                else {
                    admission = Some(held);
                    continue;
                };
                let mut host = executor::QueueCheckExecutor::new(config.clone());
                let stop = || self.housekeeping_passes.stopping();
                match vault.run_queue_check(&work, &mut host, &stop) {
                    Ok(_) => checked += 1,
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "queue check did not settle");
                    }
                }
                drop(held);
            }
            ran += checked;
            if moved == 0 && checked == 0 {
                break;
            }
        }
        Ok(ran)
    }

    /// Every enrolled queue's next steps, each step at most once a pass and
    /// each under an admission of its own; how many moved, or `None` when
    /// the host stops or its gate refuses.
    fn drive_queues(
        &self,
        admission: &mut Option<Box<dyn Send>>,
        admit: &HousekeepingAdmission,
        pass: QueueDrivePass,
        driven: &mut Vec<(String, QueueWork)>,
    ) -> oneiron::Result<Option<usize>> {
        let vault = self.vault();
        let mut moved = 0_usize;
        for config in vault.queue_driver_configurations()? {
            let works = match vault
                .queue_driver_open(&config)
                .and_then(|queue| Ok((queue.pending_work(pass)?, queue)))
            {
                Ok(found) => found,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "merge queue driver could not read a queue");
                    continue;
                }
            };
            let (works, queue) = works;
            for work in works {
                if self.housekeeping_passes.stopping() {
                    return Ok(None);
                }
                let key = (config.store.clone(), work);
                if driven.contains(&key) {
                    continue;
                }
                let Some(held) = admission.take().or_else(|| admit()) else {
                    return Ok(None);
                };
                match queue.drive_one(&config, &key.1, pass) {
                    Ok(outcome) => moved += usize::from(outcome.moved()),
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "merge queue drive step did not settle");
                    }
                }
                drop(held);
                driven.push(key);
            }
        }
        Ok(Some(moved))
    }
}
