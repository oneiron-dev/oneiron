//! The read-only lookups of a run's reader rows (ARCH-0079 #reader-forks):
//! a child's job, a parent's row, the jobs a parent spawned and every
//! settled finding a parent's finding index selects. Each is one read of
//! the run's route.

use super::{INDEX, JOBS, PARENTS, finding_key, id_at};
use crate::code_run::{
    ExecutorStorage, ReaderFindingRef, ReaderFindingSelection, ReaderJob, ReaderJobState,
    ReaderParent, SelectedFinding,
};
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

    /// Every settled finding of `parent_run`'s children its finding index
    /// selects, in one read of the run's route (FIX 6352): each Done or
    /// Partial child of the parent whose finding a reference selects (its
    /// exact occurrence ref, or the first reporter of an unqualified content
    /// handle), with each reference that selects it, and the child cutoff
    /// the parent's row records. The index selects a job; its persisted
    /// finding must still match the reference. A lookup of any one
    /// reference reads from it the answer the index gives in this read.
    pub(crate) fn reader_finding_selection(
        &self,
        parent_run: EntityId,
    ) -> Result<ReaderFindingSelection> {
        self.reader_read(|txn, dbs| {
            let prefix = finding_key(parent_run, "");
            let mut findings: Vec<SelectedFinding> = Vec::new();
            for row in INDEX.iter_from(&dbs, txn, &prefix)? {
                let (key, task) = row?;
                let Some(reference) = key
                    .get(prefix.len()..)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                else {
                    continue;
                };
                let task = id_at(&task, 0)?;
                let selects = |finding: &ReaderFindingRef| -> Result<bool> {
                    Ok(finding.handle == reference || finding.reference()? == reference)
                };
                if let Some(held) = findings.iter_mut().find(|held| held.task == task) {
                    if selects(&held.finding)? {
                        held.references.push(reference.to_owned());
                    }
                    continue;
                }
                let Some(finding) = JOBS
                    .get(&dbs, txn, &task)?
                    .filter(|job| {
                        job.binding.parent_run == parent_run
                            && matches!(
                                job.state,
                                ReaderJobState::Done | ReaderJobState::Partial { .. }
                            )
                    })
                    .and_then(|job| job.finding)
                else {
                    continue;
                };
                if selects(&finding)? {
                    findings.push(SelectedFinding {
                        task,
                        finding,
                        references: vec![reference.to_owned()],
                    });
                }
            }
            let cutoff_unix_ms = PARENTS
                .get(&dbs, txn, &parent_run)?
                .map(|parent| parent.deadline.child_cutoff());
            Ok(ReaderFindingSelection {
                findings,
                cutoff_unix_ms,
            })
        })
    }
}
