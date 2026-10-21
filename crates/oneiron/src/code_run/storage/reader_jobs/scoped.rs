//! A host's scoped child (FIX 7507 PR2), queued on its parent's reader rows
//! as every child of the parent is: the same task, run and attempt ids, the
//! same parent row with its clock, meter and frozen model list, the same
//! queue and the same runner. Its kind keeps what its loan lent it, and its
//! binding the parent attempt lease it borrowed, if any (FIX 7507 PR3),
//! which its claim, report, settle and recovery check in their own
//! transactions: a lost lease settles it, and nothing renews one.

use heed::RoTxn;

use super::{NewReaderJob, ReaderJobs, ReaderTxn, SpawnAdmission, SpendBook};
use crate::attempt_queue::{AttemptQueue, BorrowedAttemptLease};
use crate::code_run::{
    ExecutorStorage, ReaderActor, ReaderJob, ReaderJobKind, ReaderJobState, ReaderRoute,
    ReaderSpawnReceipt, SCOPED_CHILD_AUTHORITY_LAPSED, SCOPED_CHILD_PARENT_LEASE_LOST,
    ScopedChildLoan, SpawnHostSeat, reader_attempt_id, reader_run_id, reader_task_id,
    valid_reader_key, vault_ref,
};
use crate::limit_ask::EngineLimit;
use crate::{EdgeActorClass, EntityId, Result};

/// A spawn whose key had queued a job other than the one its loan lends:
/// another kind, another loan, another actor or another route. Nothing is
/// written, and the stored job is never widened or reread as this one.
const SCOPED_CHILD_SPAWN_CHANGED: &str = "scoped_child_spawn_changed";

/// A loan made on a route other than these jobs'.
const SCOPED_CHILD_ROUTE_MISMATCH: &str = "scoped_child_route_mismatch";

/// A loan that borrowed one parent attempt lease, spawned under a seat whose
/// run holds another: the child is never bound to either by guess.
const SCOPED_CHILD_LEASE_MISMATCH: &str = "scoped_child_lease_mismatch";

impl ReaderJobs<'_> {
    /// Queues the scoped child `loan` lends under `intent_key`, asked `ask`,
    /// at `now_ms`, as a child of the loan's parent run under `seat`: its
    /// parent row is made from `seat` at the parent's first spawn and read
    /// from there after, as a read child's is. The runner is woken once it
    /// is queued. The same key answers the job it already queued, only
    /// while that job is this loan's own; any other is refused.
    ///
    /// The job borrows the parent attempt lease its loan borrowed
    /// ([`ScopedChildLoan::with_parent_attempt`]), else the one `seat`'s run
    /// holds, and lives only while it holds. A host attempt's (System) loan
    /// spawns only on a lease it borrowed itself, where its ports were held
    /// to its parent's (FIX 7732).
    ///
    /// The answer's `Err` names why nothing was queued:
    /// `reader_spawn_invalid_intent_key`, `scoped_child_route_mismatch`,
    /// `scoped_child_lease_mismatch`, `scoped_child_authority_lapsed`,
    /// `scoped_child_spawn_changed`, `reader_spawn_past_cutoff` or
    /// `reader_spawn_unmetered`.
    ///
    /// # Errors
    ///
    /// The route's own read and write errors.
    pub fn spawn_scoped(
        &self,
        seat: &SpawnHostSeat,
        loan: &ScopedChildLoan,
        intent_key: &str,
        ask: String,
        now_ms: u64,
    ) -> Result<std::result::Result<ReaderSpawnReceipt, &'static str>> {
        if !valid_reader_key(intent_key) {
            return Ok(Err("reader_spawn_invalid_intent_key"));
        }
        let storage = &self.storage;
        let route = ReaderRoute {
            vault: vault_ref(storage.vault_id()),
            session_ref: storage.session_ref().map(str::to_owned),
            participant: storage.participant(),
        };
        let Some(source) = loan.spec.source().filter(|_| route == loan.route) else {
            return Ok(Err(SCOPED_CHILD_ROUTE_MISMATCH));
        };
        let parent_lease = match (&loan.parent_lease, &seat.parent_lease) {
            (Some(lent), Some(held)) if lent != held => {
                return Ok(Err(SCOPED_CHILD_LEASE_MISMATCH));
            }
            (Some(lease), _) | (None, Some(lease)) => Some(lease.clone()),
            (None, None) => None,
        };
        if loan.actor.actor_class() == EdgeActorClass::System && loan.parent_lease.is_none() {
            return Ok(Err(SCOPED_CHILD_AUTHORITY_LAPSED));
        }
        let task = reader_task_id(loan.parent_run, intent_key)?;
        let actor = ReaderActor::of(loan.actor);
        let kind = ReaderJobKind::ScopedAgent {
            spec: loan.spec.clone(),
        };
        let new = NewReaderJob {
            task,
            attempt: reader_attempt_id(task)?,
            run: reader_run_id(task)?,
            parent_run: loan.parent_run,
            actor,
            source: source.clone(),
            route: route.clone(),
            kind: kind.clone(),
            ask,
            parent_lease: parent_lease.clone(),
        };
        let (job, replay) = match storage.spawn_reader_job(seat, new, now_ms)? {
            SpawnAdmission::Queued { job, queued } => {
                // The backlog row asks on its crossing edge and keeps
                // queueing: it never refuses and never bounds the window.
                let watch = storage.limit_watch();
                let bound = watch.bound(EngineLimit::CodeReaderBacklog);
                if queued == bound.saturating_add(1) {
                    watch.crossed(EngineLimit::CodeReaderBacklog, bound, queued);
                }
                storage.wake_reader_runner(job.task);
                (job, false)
            }
            SpawnAdmission::Existing(job) => {
                if job.kind != kind
                    || job.binding.actor != actor
                    || job.binding.route != route
                    || job.binding.parent_lease != parent_lease
                {
                    return Ok(Err(SCOPED_CHILD_SPAWN_CHANGED));
                }
                (job, true)
            }
            SpawnAdmission::PastCutoff => return Ok(Err("reader_spawn_past_cutoff")),
            SpawnAdmission::Unmetered => return Ok(Err("reader_spawn_unmetered")),
        };
        Ok(Ok(ReaderSpawnReceipt {
            task: job.task,
            attempt: crate::entity_id::bytes_to_hex_lower(job.attempt.as_bytes()),
            run: job.run,
            cutoff_unix_ms: job.binding.child_cutoff_unix_ms,
            state: job.state.word().to_owned(),
            replay,
        }))
    }

    /// Whether child `task`, claimed at `generation`, is still active and,
    /// when it borrowed its parent attempt's lease, that lease still holds
    /// (`scoped_parent_lease_holds`): the runner's admission before a seat
    /// or a model entry, which each committing transaction makes again.
    ///
    /// # Errors
    ///
    /// The route's own read errors.
    pub fn scoped_parent_holds(&self, task: EntityId, generation: u32) -> Result<bool> {
        let Some(job) = self
            .storage
            .reader_job(task)?
            .filter(|job| job.state == ReaderJobState::Active && job.generation == generation)
        else {
            return Ok(false);
        };
        self.storage.scoped_parent_lease_holds(&job)
    }
}

impl SpendBook<'_> {
    /// Whether `lease`, the parent attempt lease a scoped child borrowed,
    /// still holds in the caller's snapshot: a base row as the spend scopes
    /// are, read for its ids and generation alone.
    fn lease_holds_in_txn(self, txn: &RoTxn<'_>, lease: &BorrowedAttemptLease) -> Result<bool> {
        lease.holds_in(&AttemptQueue::new(self.0), txn)
    }

    /// [`Self::lease_holds_in_txn`] in a fresh snapshot.
    fn lease_holds(self, lease: &BorrowedAttemptLease) -> Result<bool> {
        let txn = self.0.store.env.read_txn()?;
        self.lease_holds_in_txn(&txn, lease)
    }
}

impl ReaderTxn<'_, '_> {
    /// `scoped_parent_lease_holds` (CALLS, open): whether `job` may still
    /// commit under the parent attempt lease it borrowed, in this
    /// transaction. A job that borrowed none (a read, a summary, a scoped
    /// child lent no lease) always may: it outlives its spawner as before.
    /// One that did, only while that lease holds; nothing renews it.
    pub(super) fn scoped_parent_lease_holds(&self, job: &ReaderJob) -> Result<bool> {
        match job.scoped_parent_lease() {
            Some(lease) => self.spend.lease_holds_in_txn(&*self.txn, lease),
            None => Ok(true),
        }
    }

    /// Settles `job`, whose borrowed parent lease no longer holds, at
    /// `now_ms`: partial with its latest committed finding, failed with
    /// none, each `scoped_child_parent_lease_lost`, fenced past its
    /// generation so a late report or read is refused. It is never requeued
    /// under another lease.
    pub(super) fn settle_lease_lost(
        &mut self,
        mut job: ReaderJob,
        now_ms: u64,
    ) -> Result<ReaderJob> {
        let finding = self.committed_finding(&job)?;
        if job.state == ReaderJobState::Active {
            job.generation = job.generation.saturating_add(1);
        }
        let reason = SCOPED_CHILD_PARENT_LEASE_LOST.to_owned();
        let state = if finding.is_some() {
            ReaderJobState::Partial { reason }
        } else {
            ReaderJobState::Failed { reason }
        };
        self.settle(job, state, finding, now_ms)
    }
}

impl ExecutorStorage<'_> {
    /// Whether `job` may still act under the parent attempt lease it
    /// borrowed, in a fresh snapshot (`scoped_parent_lease_holds`): an
    /// admission check before a read, a port or a model entry, which every
    /// committing transaction makes again. A job that borrowed none may.
    pub(crate) fn scoped_parent_lease_holds(&self, job: &ReaderJob) -> Result<bool> {
        job.scoped_parent_lease()
            .map_or(Ok(true), |lease| self.spend_book().lease_holds(lease))
    }
}
