//! The read-only lookups of a run's reader rows (ARCH-0079 #reader-forks):
//! a child's job, a parent's row, the jobs a parent spawned and the settled
//! finding a parent names. Each is one read of the run's route.

use super::{INDEX, JOBS, PARENTS, finding_key, id_at};
use crate::code_run::{ExecutorStorage, ReaderJob, ReaderJobState, ReaderParent};
use crate::{EntityId, Result};

impl ExecutorStorage<'_> {
    pub(crate) fn reader_job(&self, task: EntityId) -> Result<Option<ReaderJob>> {
        self.reader_read(|txn, dbs| JOBS.get(&dbs, txn, &task))
    }

    pub(crate) fn reader_parent(&self, run: EntityId) -> Result<Option<ReaderParent>> {
        self.reader_read(|txn, dbs| PARENTS.get(&dbs, txn, &run))
    }

    /// The jobs among `tasks` that `parent_run` spawned itself, in one read
    /// of the run's route: a task with no row, or another parent's, is left
    /// out.
    pub(crate) fn own_reader_jobs(
        &self,
        parent_run: EntityId,
        tasks: &[EntityId],
    ) -> Result<Vec<ReaderJob>> {
        self.reader_read(|txn, dbs| {
            let mut own = Vec::with_capacity(tasks.len());
            for task in tasks {
                if let Some(job) = JOBS
                    .get(&dbs, txn, task)?
                    .filter(|job| job.binding.parent_run == parent_run)
                {
                    own.push(job);
                }
            }
            Ok(own)
        })
    }

    /// The settled child finding named by its exact occurrence ref, or the
    /// first reporter of an unqualified content handle. The index selects a
    /// job; its persisted finding must still match the reference.
    pub(crate) fn reader_finding(
        &self,
        parent_run: EntityId,
        reference: &str,
    ) -> Result<Option<ReaderJob>> {
        self.reader_read(|txn, dbs| {
            let Some(task) = INDEX.get(&dbs, txn, &finding_key(parent_run, reference))? else {
                return Ok(None);
            };
            let task = id_at(&task, 0)?;
            let Some(job) = JOBS.get(&dbs, txn, &task)?.filter(|job| {
                job.binding.parent_run == parent_run
                    && matches!(
                        job.state,
                        ReaderJobState::Done | ReaderJobState::Partial { .. }
                    )
            }) else {
                return Ok(None);
            };
            let Some(finding) = &job.finding else {
                return Ok(None);
            };
            if finding.handle != reference && finding.reference()? != reference {
                return Ok(None);
            }
            Ok(Some(job))
        })
    }
}
