//! A host's scoped child (FIX 7507 PR2), queued on its parent's reader rows
//! as every child of the parent is: the same task, run and attempt ids, the
//! same parent row with its clock, meter and frozen model list, the same
//! queue and the same runner. Its kind keeps what its loan lent it.

use super::{NewReaderJob, ReaderJobs, SpawnAdmission};
use crate::Result;
use crate::code_run::{
    ReaderActor, ReaderJobKind, ReaderRoute, ReaderSpawnReceipt, ScopedChildLoan, SpawnHostSeat,
    reader_attempt_id, reader_run_id, reader_task_id, valid_reader_key, vault_ref,
};
use crate::limit_ask::EngineLimit;

/// A spawn whose key had queued a job other than the one its loan lends:
/// another kind, another loan, another actor or another route. Nothing is
/// written, and the stored job is never widened or reread as this one.
const SCOPED_CHILD_SPAWN_CHANGED: &str = "scoped_child_spawn_changed";

/// A loan made on a route other than these jobs'.
const SCOPED_CHILD_ROUTE_MISMATCH: &str = "scoped_child_route_mismatch";

impl ReaderJobs<'_> {
    /// Queues the scoped child `loan` lends under `intent_key`, asked `ask`,
    /// at `now_ms`, as a child of the loan's parent run under `seat`: its
    /// parent row is made from `seat` at the parent's first spawn and read
    /// from there after, as a read child's is. The runner is woken once it
    /// is queued. The same key answers the job it already queued, only
    /// while that job is this loan's own; any other is refused.
    ///
    /// The answer's `Err` names why nothing was queued:
    /// `reader_spawn_invalid_intent_key`, `scoped_child_route_mismatch`,
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
                if job.kind != kind || job.binding.actor != actor || job.binding.route != route {
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
}
