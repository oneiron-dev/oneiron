//! First-spawn parent freezing and reader job publication.

use super::{
    DUE_JOB, ExecutorStorage, NewReaderJob, ReaderJob, ReaderJobState, ReaderParent, Result,
    SpawnAdmission, child_key, due_key, queued_key,
};
use crate::code_run::{SpawnHostSeat, SpawnParentBinding, reader_job_cutoff};

impl ExecutorStorage<'_> {
    /// Queues one child of `new.parent_run`, its parent row made from `seat`
    /// at its first spawn and read from there after: the clock, the meter
    /// and the model list are fixed once. A child past its cutoff (a
    /// summary's is the outer one, `reader_job_cutoff`), or under a scope
    /// that is gone, is refused with nothing written; one on the host's
    /// meter is admitted with no ledger lookup.
    pub(crate) fn spawn_reader_job(
        &self,
        seat: &SpawnHostSeat,
        new: NewReaderJob,
        now_ms: u64,
    ) -> Result<SpawnAdmission> {
        self.reader_txn(|tx| {
            if let Some(job) = tx.job(new.task)? {
                return Ok(SpawnAdmission::Existing(Box::new(job)));
            }
            let mut parent = tx.parent(new.parent_run)?.unwrap_or_else(|| ReaderParent {
                deadline: seat.deadline,
                spend: seat.spend.clone(),
                hold_units: seat.hold_units,
                listed: seat.listed.clone(),
                project: seat.project,
                next_ordinal: 0,
                queued: 0,
                active: 0,
            });
            // A summary is the fold the parent's reserve is kept for, so it
            // may run into it; a read and a scoped child stop before it.
            let cutoff = reader_job_cutoff(&new.kind, &parent.deadline);
            if now_ms >= cutoff {
                return Ok(SpawnAdmission::PastCutoff);
            }
            if let Some(scope) = parent.spend.scope()
                && tx.spend.open_scope_in_txn(&*tx.txn, scope)?.is_none()
            {
                return Ok(SpawnAdmission::Unmetered);
            }
            let job = ReaderJob {
                task: new.task,
                attempt: new.attempt,
                run: new.run,
                binding: SpawnParentBinding {
                    parent_run: new.parent_run,
                    actor: new.actor,
                    source: new.source,
                    route: new.route,
                    spend: parent.spend.clone(),
                    deadline: parent.deadline,
                    child_cutoff_unix_ms: cutoff,
                    // A read and a summary alike take the list the
                    // spawning run froze at its first spawn (FIX 4539), never
                    // a later entry's in its place.
                    listed: parent.listed.clone(),
                    project: parent.project,
                    parent_lease: new.parent_lease,
                },
                kind: new.kind,
                ask: new.ask,
                state: ReaderJobState::Queued,
                generation: 0,
                finding: None,
                enqueued_at_ms: now_ms,
                settled_at_ms: None,
            };
            let ordinal = parent.next_ordinal;
            parent.next_ordinal = parent.next_ordinal.saturating_add(1);
            parent.queued = parent.queued.saturating_add(1);
            tx.put_job(&job)?;
            tx.put_index(&child_key(new.parent_run, ordinal, job.task), &[])?;
            tx.put_index(&queued_key(now_ms, job.task), &[])?;
            tx.put_index(&due_key(cutoff, job.task), DUE_JOB)?;
            tx.put_parent(new.parent_run, &parent)?;
            Ok(SpawnAdmission::Queued {
                job: Box::new(job),
                queued: parent.queued,
            })
        })
    }
}
