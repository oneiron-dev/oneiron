//! The backup before an idle reap (`prepare_idle_reap`, Engine 10-20 backup
//! shipper row (a), co-signed with LC).
//!
//! One attempt at a time. The first call starts it: the freeze
//! `prepare_reap` runs, which reads the writes in flight by kind (FIX
//! 6902). An owner write among them leaves the vault busy. Otherwise the
//! background passes, which take no new unit once frozen, are waited for,
//! by the attempt's deadline; then the drain and the export (the export
//! alone once that wait ran out, FIX 6955), and, when the vault was quiet,
//! one backup job on a blocking thread of its own
//! ([`OwnerHost::back_up_before_idle`]). Every later call joins it, and none
//! starts a second drain or a second backup. A call answers once the attempt
//! settles, or once its deadline passes, [`IDLE_REAP_PREPARATION_SECS`] after
//! its first call; every answer carries the writes in flight at the freeze.
//!
//! The deadline is a phase change the attempt owns, not a timeout on its
//! job: whoever looks at the attempt past it, a call or the job itself,
//! settles it failed, `backup_busy` while another backup held the lock, or
//! was in flight while background passes were waited for, and
//! `deadline_exceeded` otherwise. Neither the job nor a background pass is
//! aborted: a Dreamer pass the freeze pauses stops at its next boundary
//! (FIX 6909), and the unit in hand finishes. Each counts among the writes
//! in flight until it ends, so the vault never reads quiescent while one
//! writes, and what the job finishes after the deadline is never recorded as
//! covered (`owner::backup::finalize`).
//!
//! `reap_abort` drops the attempt before the vault thaws: a call still
//! waiting on it is refused, and its job, should it finish, records nothing.
//! The next call starts a new attempt, whose backup waits for that job's
//! lock. A stop waits for every job started to end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron_vault_contract::{
    BackupCoverageWire, CtlResponse, IDLE_REAP_PREPARATION_SECS, IDLE_REAP_SCHEMA_VERSION,
    IdleBackupFailure, IdleBackupState, IdleBackupWire, IdleReapWire, LedgerReportHead,
};
use rand_core::{OsRng, RngCore};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::ManagedState;
use super::admission::{InFlightCounts, WriteKind};
use crate::managed::ManagedError;
use crate::owner::schedule::{OwnerHost, PreIdleAttempt, PreIdleBackup};

/// How long an attempt's backup has from its first call.
const PREPARATION: Duration = Duration::from_secs(IDLE_REAP_PREPARATION_SECS);

/// A managed vault's attempts at a backup before an idle reap.
pub(super) struct IdleBackup {
    /// The attempt that stands, if any.
    attempt: Mutex<Option<Attempt>>,
    /// Bumped on every change to it, so a waiting call looks again.
    changed: watch::Sender<u64>,
    /// Every job started, kept until it ends.
    jobs: Mutex<Jobs>,
}

/// The backup jobs an [`IdleBackup`] started.
#[derive(Default)]
struct Jobs {
    /// Set on stop: no job starts after.
    stopped: bool,
    running: Vec<JoinHandle<()>>,
}

impl Default for IdleBackup {
    fn default() -> Self {
        Self {
            attempt: Mutex::new(None),
            changed: watch::channel(0).0,
            jobs: Mutex::new(Jobs::default()),
        }
    }
}

/// One attempt at a backup before an idle reap.
struct Attempt {
    /// 16 random bytes as 32 lowercase hex digits.
    id: String,
    deadline: Instant,
    phase: Phase,
    /// The freeze, drain and export's report, once they are done.
    report: Option<Report>,
    /// Whether its backup job is running.
    job_running: bool,
}

enum Phase {
    /// Freezing, draining and exporting.
    Preparing,
    /// Waiting for the background passes in flight at the freeze to end;
    /// the owner host's backup jobs are read at the deadline.
    Draining(Option<Arc<OwnerHost>>),
    /// The job waits for the backup lock.
    Locking,
    /// The job holds the lock and writes.
    Writing,
    Settled(Settled),
}

enum Settled {
    /// A backup covers the vault as it stands.
    Covered {
        reused: bool,
        artifact: String,
        coverage: BackupCoverageWire,
    },
    Failed(IdleBackupFailure),
}

/// What the freeze, drain and export found.
struct Report {
    /// No owner write was in flight at the freeze, the background passes
    /// then in flight ended before the drain, the lease table drained, and
    /// no sync session could still commit.
    quiet: bool,
    /// The admitted writes in flight at the freeze, by kind.
    in_flight_at_freeze: InFlightCounts,
    /// The wake ledger report the freeze holds for the supervisor's pull.
    ledger: LedgerReportHead,
}

impl Attempt {
    /// Settles the attempt failed once its deadline passed, `backup_busy`
    /// while its job waited for the lock, or while background passes were
    /// waited for with a backup job in flight, and `deadline_exceeded`
    /// otherwise; a settled one stays as it is.
    fn expire(&mut self) {
        if Instant::now() < self.deadline {
            return;
        }
        let reason = match &self.phase {
            Phase::Settled(_) => return,
            Phase::Locking => IdleBackupFailure::BackupBusy,
            Phase::Draining(Some(host)) if host.backup_jobs() > 0 => IdleBackupFailure::BackupBusy,
            Phase::Preparing | Phase::Draining(_) | Phase::Writing => {
                IdleBackupFailure::DeadlineExceeded
            }
        };
        self.phase = Phase::Settled(Settled::Failed(reason));
    }

    /// Settles it failed for `reason`, unless it settled already.
    fn fail(&mut self, reason: IdleBackupFailure) {
        self.expire();
        if !matches!(self.phase, Phase::Settled(_)) {
            self.phase = Phase::Settled(Settled::Failed(reason));
        }
    }

    /// Whether a call answers now: its report is in, and it settled with its
    /// job ended, or its deadline passed.
    fn answerable(&self) -> bool {
        self.report.is_some()
            && matches!(self.phase, Phase::Settled(_))
            && (!self.job_running || Instant::now() >= self.deadline)
    }
}

impl IdleBackup {
    fn attempt(&self) -> MutexGuard<'_, Option<Attempt>> {
        self.attempt.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes every waiting call to look at the attempt again.
    fn notify(&self) {
        self.changed
            .send_modify(|seen| *seen = seen.wrapping_add(1));
    }

    /// Runs `change` on the attempt `id` while it stands, then wakes every
    /// waiting call; `None` once it was dropped.
    fn with_attempt<T>(&self, id: &str, change: impl FnOnce(&mut Attempt) -> T) -> Option<T> {
        let done = self
            .attempt()
            .as_mut()
            .filter(|attempt| attempt.id == id)
            .map(change);
        self.notify();
        done
    }

    /// The attempt that stands, or a new one; `true` when new.
    fn join_or_start(&self) -> (String, bool) {
        let mut attempt = self.attempt();
        if let Some(standing) = attempt.as_ref() {
            return (standing.id.clone(), false);
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let id = oneiron_vault_contract::hex(&id);
        *attempt = Some(Attempt {
            id: id.clone(),
            deadline: Instant::now() + PREPARATION,
            phase: Phase::Preparing,
            report: None,
            job_running: false,
        });
        (id, true)
    }

    /// The deadline of the attempt `id`, while it stands.
    fn deadline(&self, id: &str) -> Option<Instant> {
        self.attempt()
            .as_ref()
            .filter(|attempt| attempt.id == id)
            .map(|attempt| attempt.deadline)
    }

    /// Drops the attempt that stands, on `reap_abort`: no call answers for
    /// it, and its job records nothing.
    pub(super) fn drop_attempt(&self) {
        *self.attempt() = None;
        self.notify();
    }

    /// Drops the attempt `id` when it still stands: its freeze, drain or
    /// export failed.
    fn drop_failed(&self, id: &str) {
        let mut attempt = self.attempt();
        if attempt.as_ref().is_some_and(|attempt| attempt.id == id) {
            *attempt = None;
        }
        drop(attempt);
        self.notify();
    }

    fn jobs(&self) -> MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for every job started to end, on stop: none is cancelled, and
    /// none starts after.
    pub(super) async fn stopped(&self) {
        let running = {
            let mut jobs = self.jobs();
            jobs.stopped = true;
            std::mem::take(&mut jobs.running)
        };
        for job in running {
            let _ = job.await;
        }
    }
}

/// The attempt a backup job runs for, as the job sees it.
struct JobAttempt {
    idle: Arc<IdleBackup>,
    id: String,
}

impl PreIdleAttempt for JobAttempt {
    fn id(&self) -> &str {
        &self.id
    }

    fn locked(&self) -> bool {
        self.idle
            .with_attempt(&self.id, |attempt| {
                attempt.expire();
                let locking = matches!(attempt.phase, Phase::Locking);
                if locking {
                    attempt.phase = Phase::Writing;
                }
                locking
            })
            .unwrap_or(false)
    }

    fn standing(&self) -> bool {
        self.idle
            .with_attempt(&self.id, |attempt| {
                attempt.expire();
                matches!(attempt.phase, Phase::Writing)
            })
            .unwrap_or(false)
    }

    fn settle(&self, done: &PreIdleBackup) -> bool {
        self.idle
            .with_attempt(&self.id, |attempt| {
                attempt.expire();
                let writing = matches!(attempt.phase, Phase::Writing);
                if writing {
                    attempt.phase = Phase::Settled(Settled::Covered {
                        reused: done.reused,
                        artifact: done.artifact.clone(),
                        coverage: BackupCoverageWire {
                            incarnation: oneiron_vault_contract::hex(&done.covered.incarnation()),
                            db_txn: done.covered.db_txn().to_string(),
                            custody_epoch: done.covered.custody_epoch().to_string(),
                            custody_seq: done.covered.custody_seq().to_string(),
                        },
                    });
                }
                writing
            })
            .unwrap_or(false)
    }
}

impl ManagedState {
    /// Answers `prepare_idle_reap`: starts an attempt or joins the one that
    /// stands, and answers once it settles or its deadline passes. A freeze,
    /// drain or export that fails answers as `prepare_reap`'s does.
    pub(super) async fn prepare_idle_reap(&self) -> Result<CtlResponse, ManagedError> {
        let idle = Arc::clone(&self.idle_backup);
        let mut changes = idle.changed.subscribe();
        let (id, first) = idle.join_or_start();
        if first {
            self.prepare_attempt(&id).await?;
        }
        loop {
            let deadline = {
                let mut attempt = idle.attempt();
                let Some(attempt) = attempt.as_mut().filter(|attempt| attempt.id == id) else {
                    return Err(ManagedError::CtlRequestRefused {
                        reason: "the idle reap preparation was aborted".to_owned(),
                    });
                };
                attempt.expire();
                if attempt.answerable()
                    && let Some(report) = attempt.report.as_ref()
                {
                    return Ok(self.idle_reply(attempt, report));
                }
                attempt.deadline
            };
            let changed = if Instant::now() < deadline {
                tokio::select! {
                    changed = changes.changed() => changed,
                    () = tokio::time::sleep_until(deadline) => Ok(()),
                }
            } else {
                changes.changed().await
            };
            if changed.is_err() {
                return Err(ManagedError::CtlRequestRefused {
                    reason: "the idle reap preparation stopped".to_owned(),
                });
            }
        }
    }

    /// The first call's part: the freeze; when no owner write was in flight
    /// at it, the wait for the background passes then in flight; the drain
    /// and the export; then the backup job, unless a write was in flight, a
    /// background pass outlasted the deadline, the deadline passed or the
    /// attempt was dropped meanwhile.
    async fn prepare_attempt(&self, id: &str) -> Result<(), ManagedError> {
        let idle = &self.idle_backup;
        let at_freeze = match self.freeze_counted() {
            Ok(at_freeze) => at_freeze,
            Err(error) => {
                idle.drop_failed(id);
                return Err(error);
            }
        };
        tracing::info!(
            attempt_id = id,
            owner_write = at_freeze.owner_write,
            background_tagging = at_freeze.background_tagging,
            dreamer = at_freeze.dreamer,
            background_other = at_freeze.background_other,
            backup = at_freeze.backup,
            "the idle reap preparation froze the vault; the writes in flight by kind"
        );
        let host = self.server.owner_host.clone();
        // An owner write at the freeze leaves the vault busy, whenever it
        // ends. Background passes take no new unit once frozen; those in
        // flight are waited for, so the export comes after their last write.
        let owner_idle = at_freeze.owner_write == 0;
        let background_drained = owner_idle && self.drain_background(id, host.clone()).await;
        // A wait the deadline cut short leaves the vault busy: no lease drain
        // starts past it, and the export answers at once (FIX 6955).
        let waited_out = owner_idle && !background_drained;
        // The deadline may have passed while the last pass ended: no lease
        // drain starts past it either (FIX 11066).
        let waited_out = waited_out
            || (background_drained && idle.deadline(id).is_some_and(|at| Instant::now() >= at));
        // A drain still under way at the deadline is cut there, and the
        // export answers at once, as the waited-out path does (FIX 11742).
        let outcome = self
            .drain_export(at_freeze, !waited_out, idle.deadline(id))
            .await;
        let prepared = match outcome {
            Ok(prepared) => prepared,
            Err(error) => {
                idle.drop_failed(id);
                return Err(error);
            }
        };
        let quiet = background_drained && prepared.drained && !self.live_sync_writer();
        let start = idle
            .with_attempt(id, |attempt| {
                attempt.report = Some(Report {
                    quiet,
                    in_flight_at_freeze: at_freeze,
                    ledger: prepared.report.head,
                });
                attempt.expire();
                if matches!(attempt.phase, Phase::Settled(_)) {
                    return false;
                }
                // A wait the deadline cut short settled in `expire`, above.
                match (&host, quiet) {
                    (_, false) => attempt.fail(IdleBackupFailure::WritersBusy),
                    (None, true) => attempt.fail(IdleBackupFailure::SnapshotFailed),
                    (Some(_), true) => {
                        attempt.phase = Phase::Locking;
                        attempt.job_running = true;
                    }
                }
                attempt.job_running
            })
            .unwrap_or(false);
        if let (true, Some(host)) = (start, host)
            && !self.start_job(host, id.to_owned())
        {
            // Stopping: no backup starts.
            idle.with_attempt(id, |attempt| {
                attempt.fail(IdleBackupFailure::WorkerFailed);
                attempt.job_running = false;
            });
        }
        Ok(())
    }

    /// Waits for the background passes in flight, and device sync's run and
    /// refresh, which pause at the freeze (FIX 5127), to end: `true` once
    /// none is, `false` once the attempt `id`'s deadline passed, settling it
    /// as it stands then, or once the attempt was dropped. It wakes as each
    /// ends and as the attempt changes, cancels nothing and releases
    /// nothing. `host`'s backup jobs decide the reason at the deadline.
    async fn drain_background(&self, id: &str, host: Option<Arc<OwnerHost>>) -> bool {
        let idle = &self.idle_backup;
        let mut ended = self.admission.ended();
        let mut changes = idle.changed.subscribe();
        idle.with_attempt(id, |attempt| {
            if matches!(attempt.phase, Phase::Preparing) {
                attempt.phase = Phase::Draining(host);
            }
        });
        loop {
            if self.admission.in_flight().waited_for() == 0 {
                idle.with_attempt(id, |attempt| {
                    if matches!(attempt.phase, Phase::Draining(_)) {
                        attempt.phase = Phase::Preparing;
                    }
                });
                return true;
            }
            let Some(deadline) = idle.deadline(id) else {
                return false;
            };
            if Instant::now() >= deadline {
                idle.with_attempt(id, Attempt::expire);
                return false;
            }
            tokio::select! {
                _ = ended.changed() => {}
                _ = changes.changed() => {}
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    /// Starts the attempt `id`'s backup job: on a blocking thread, counted
    /// among the writes in flight and as a backup job until it ends, its
    /// handle kept for the stop. Its failure settles the attempt, unless it
    /// settled already; a job that stops without an answer is
    /// `worker_failed`. `false`, and nothing started, once stopping.
    fn start_job(&self, host: Arc<OwnerHost>, id: String) -> bool {
        let idle = Arc::clone(&self.idle_backup);
        let mut jobs = idle.jobs();
        if jobs.stopped {
            return false;
        }
        let in_flight = self.admission.hold(WriteKind::Backup);
        let server = Arc::clone(&self.server);
        let attempt = JobAttempt {
            idle: Arc::clone(&idle),
            id: id.clone(),
        };
        let blocking = tokio::task::spawn_blocking(move || {
            let _in_flight = in_flight;
            let _job = host.backup_job();
            host.back_up_before_idle(server.vault(), &attempt)
        });
        let job = tokio::spawn({
            let idle = Arc::clone(&idle);
            async move {
                let failed = match blocking.await {
                    Ok(Ok(())) => None,
                    Ok(Err(reason)) => Some(reason),
                    Err(error) => {
                        tracing::warn!(
                            panicked = error.is_panic(),
                            reason = IdleBackupFailure::WorkerFailed.as_str(),
                            "the backup before an idle reap stopped without an answer"
                        );
                        Some(IdleBackupFailure::WorkerFailed)
                    }
                };
                idle.with_attempt(&id, |attempt| {
                    if let Some(reason) = failed {
                        attempt.fail(reason);
                    }
                    attempt.job_running = false;
                });
            }
        });
        jobs.running.retain(|job| !job.is_finished());
        jobs.running.push(job);
        true
    }

    /// The answer for `attempt` and its `report`: quiescent only when its
    /// freeze found the vault quiet, it is still frozen, and no write of any
    /// kind, backup or sync session is in flight now.
    fn idle_reply(&self, attempt: &Attempt, report: &Report) -> CtlResponse {
        let quiescent = report.quiet
            && self.is_frozen()
            && !self.live_sync_writer()
            && self.admission.in_flight().total() == 0;
        let pending = IdleBackupWire {
            state: IdleBackupState::Pending,
            attempt_id: attempt.id.clone(),
            artifact_id: None,
            coverage: None,
            reason: None,
            retryable: false,
        };
        let backup = match &attempt.phase {
            Phase::Settled(Settled::Covered {
                reused,
                artifact,
                coverage,
            }) => IdleBackupWire {
                state: if *reused {
                    IdleBackupState::Reused
                } else {
                    IdleBackupState::Taken
                },
                artifact_id: Some(artifact.clone()),
                coverage: Some(coverage.clone()),
                ..pending
            },
            Phase::Settled(Settled::Failed(reason)) => IdleBackupWire {
                state: IdleBackupState::Failed,
                reason: Some(*reason),
                retryable: reason.retryable(),
                ..pending
            },
            Phase::Preparing | Phase::Draining(_) | Phase::Locking | Phase::Writing => pending,
        };
        CtlResponse::PrepareIdleReap {
            idle_reap: IdleReapWire {
                schema_version: IDLE_REAP_SCHEMA_VERSION,
                quiescent,
                in_flight_at_freeze: report.in_flight_at_freeze.wire(),
                ledger: report.ledger.clone(),
                backup,
            },
        }
    }
}
