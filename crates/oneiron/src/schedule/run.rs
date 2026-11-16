//! The one runner: every armed job that is due, in due order, within the pass's budget.

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};

use super::arm::{
    ARM_VERB, DUE, ROWS, ScheduleRow, due_key, parse_row_key, row_key, store_row_in_txn,
};
use super::{
    ArmBy, Armed, EngineZones, JobPass, JobResult, JobSpec, Late, Ran, job_named, retry_after,
};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::llm::model_pack::AccessSnapshot;
use crate::store::housekeeping_report::SweepWork;
use crate::store::housekeeping_schedule::HousekeepingBudget;

/// The most runs one pass makes, whatever its budget: a job that always answers "more" waits for
/// the next pass.
const RUNS_PER_PASS: usize = 1_000;

/// What one pass of [`Vault::run_due`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScheduleRunReport {
    pub runs: Vec<JobRun>,
}

/// One due job, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JobRun {
    pub job: String,
    /// What it is about, 32 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The occurrence it served.
    pub due_at: u64,
    pub outcome: JobOutcome,
    /// A housekeeping sweep's account of its work; not part of the report's wire form.
    #[serde(skip)]
    pub sweep_work: Option<SweepWork>,
    /// The kind of the error a failed run returned; not part of the report's wire form.
    #[serde(skip)]
    pub error_kind: Option<ErrorKind>,
}

/// What became of one due job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum JobOutcome {
    /// It ran to the end of its work.
    Done,
    /// It stopped at its budget and is due again at once.
    More,
    /// It ran to the end of its work but left items, and is due again after the backoff.
    ItemsFailed,
    /// It failed, and is due again after the backoff.
    Failed { error: String },
    /// It panicked, and is due again after the backoff.
    Panicked,
    /// An earlier run never finished (a crash or a kill): a failure.
    Interrupted,
    /// It came later than its job allows: the occurrence was dropped and never ran.
    Lapsed,
    /// The agent that armed it no longer holds the power: it was disarmed and never ran.
    Withdrawn,
    /// No job kind of its code is in this build: it waits, unrun.
    UnknownJob,
}

/// The first due-index entry due by `now`: its due time and its row's key.
fn first_due_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    now: u64,
) -> Result<Option<(u64, Vec<u8>)>> {
    for entry in DUE.iter_raw_from(&vault.store, txn, &[])? {
        let (key, _) = entry?;
        let Some((due, row_key)) = key.split_first_chunk::<8>() else {
            continue;
        };
        let due = u64::from_be_bytes(*due);
        return Ok((due <= now).then(|| (due, row_key.to_vec())));
    }
    Ok(None)
}

impl Vault {
    /// Runs every armed job that is due, in due order, within `budget`: the one runner. A host
    /// calls it through [`Vault::housekeeping`] on its own tick.
    ///
    /// # Errors
    ///
    /// Storage errors reading or writing the schedule; a job's own failure is a row of the
    /// report.
    pub fn run_due(&self, budget: HousekeepingBudget) -> Result<ScheduleRunReport> {
        self.run_due_with(budget, &AccessSnapshot::new())
    }

    /// [`Self::run_due`] on a host whose model offers hold `access`, which it lends to the runs.
    ///
    /// # Errors
    ///
    /// As [`Self::run_due`].
    pub fn run_due_with(
        &self,
        budget: HousekeepingBudget,
        access: &AccessSnapshot,
    ) -> Result<ScheduleRunReport> {
        let deadline = budget.deadline();
        self.run_due_until(&JobPass {
            deadline: &deadline,
            access,
        })
    }

    /// [`Self::run_due`] within `pass`. A pass starts at least one due job, so it makes
    /// progress however its budget was spent before it, unless its host asked it to stop.
    pub(crate) fn run_due_until(&self, pass: &JobPass<'_>) -> Result<ScheduleRunReport> {
        let _pass = self
            .housekeeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deadline = pass.deadline;
        let mut report = ScheduleRunReport::default();
        while report.runs.len() < RUNS_PER_PASS
            && !deadline.stopped()
            && (report.runs.is_empty() || !deadline.passed())
        {
            let now = self.now_recorded_at();
            let due = {
                let txn = self.store.env.read_txn()?;
                first_due_in_txn(self, &txn, now)?
            };
            let Some((due_at, key)) = due else {
                break;
            };
            report.runs.push(self.run_one(&key, due_at, pass)?);
        }
        Ok(report)
    }

    /// Runs `job` about `subject` alone, now, whatever its due time: a support holder's repair
    /// of one sweep. The run answers a "run now". A start marker an interrupted run left counts
    /// as its failure, and the job then runs. `None` when the job is not armed.
    ///
    /// # Errors
    ///
    /// Storage errors reading or writing the schedule; the job's own failure is its outcome.
    pub(crate) fn run_job_now(
        &self,
        job: &str,
        subject: Option<EntityId>,
        pass: &JobPass<'_>,
    ) -> Result<Option<JobRun>> {
        let _pass = self
            .housekeeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = row_key(job, subject);
        let due = self.with_write_txn_grouped(|txn| {
            let Some(prior) = ROWS.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let row = ScheduleRow {
                requested_at: Some(prior.requested_at.map_or(now, |earlier| earlier.min(now))),
                ..prior.clone()
            };
            store_row_in_txn(&self.store, txn, &key, Some(&prior), Some(&row))?;
            Ok(Some(row.due_at()))
        })?;
        let Some(due_at) = due else {
            return Ok(None);
        };
        let run = self.run_one(&key, due_at, pass)?;
        if run.outcome != JobOutcome::Interrupted {
            return Ok(Some(run));
        }
        // The marker is cleared and the request kept: the job runs now.
        let due_at = {
            let txn = self.store.env.read_txn()?;
            ROWS.get(&self.store, &txn, &key)?.map(|row| row.due_at())
        };
        match due_at {
            Some(due_at) => self.run_one(&key, due_at, pass).map(Some),
            None => Ok(Some(run)),
        }
    }

    /// When a stopped vault must run next for a job that wakes its host, or `None`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn schedule_wake_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        for entry in DUE.iter_raw_from(&self.store, &txn, &[])? {
            let (key, _) = entry?;
            let Some((due, row_key)) = key.split_first_chunk::<8>() else {
                continue;
            };
            let wakes = parse_row_key(row_key)
                .and_then(|(job, _)| job_named(&job))
                .is_some_and(|spec| spec.wakes_host);
            if wakes {
                return Ok(Some(u64::from_be_bytes(*due)));
            }
        }
        Ok(None)
    }

    /// One due job: checked and marked started in one write, run, and its result written in
    /// another. The result lands only on the row the run started on: a row armed again while the
    /// run ran keeps its new arming.
    fn run_one(&self, key: &[u8], due_at: u64, pass: &JobPass<'_>) -> Result<JobRun> {
        let (job, subject) = parse_row_key(key).unwrap_or_default();
        let mut run = JobRun {
            job: job.clone(),
            subject: subject.map(|subject| subject.to_hex()),
            due_at,
            outcome: JobOutcome::Done,
            sweep_work: None,
            error_kind: None,
        };
        let started = self.with_write_txn_grouped(|txn| {
            let row = ROWS.get(&self.store, txn, &key.to_vec())?;
            let Some(row) = row else {
                // A stale index entry: its row went in a write that missed it.
                DUE.delete(&self.store, txn, &due_key(due_at, key))?;
                return Ok(Err(JobOutcome::UnknownJob));
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            match job_named(&job) {
                None => {
                    // Parked until a build that knows the job: due again in a day through
                    // `resume_at`, which stands in for the occurrence's due time (the park also
                    // drops an asked-for run), so a row a newer build left in its backoff or its
                    // paged run is not found again in this pass. Its occurrence stays for the
                    // build that knows the job.
                    let parked = ScheduleRow {
                        resume_at: Some(now.saturating_add(24 * 60 * 60)),
                        requested_at: None,
                        ..row.clone()
                    };
                    store_row_in_txn(&self.store, txn, key, Some(&row), Some(&parked))?;
                    Ok(Err(JobOutcome::UnknownJob))
                }
                Some(spec) => self.start_in_txn(txn, spec, key, row, due_at, now),
            }
        })?;
        let (spec, armed) = match started {
            Ok(started) => started,
            Err(outcome) => {
                run.outcome = outcome;
                return Ok(run);
            }
        };
        let ran = catch_unwind(AssertUnwindSafe(|| (spec.run)(self, &armed, pass)));
        run.outcome = match &ran {
            Ok(Ok(result)) => match result.ran {
                Ran::Done => JobOutcome::Done,
                Ran::More { .. } => JobOutcome::More,
                Ran::ItemsFailed => JobOutcome::ItemsFailed,
                Ran::Failed => JobOutcome::Failed {
                    error: "the job reported a failure".to_owned(),
                },
            },
            Ok(Err(error)) => {
                run.error_kind = Some(error.kind());
                JobOutcome::Failed {
                    error: error.to_string(),
                }
            }
            Err(_) => JobOutcome::Panicked,
        };
        let ran = match ran {
            Ok(Ok(result)) => {
                run.sweep_work = result.sweep_work.clone();
                result
            }
            Ok(Err(_)) | Err(_) => JobResult::of(Ran::Failed),
        };
        self.with_write_txn_grouped(|txn| {
            let Some(row) = ROWS.get(&self.store, txn, &key.to_vec())? else {
                // Disarmed while it ran.
                return Ok(());
            };
            let end = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let next = if row.started_at.is_some() && row.trigger == armed.trigger {
                finished(spec, row.clone(), &ran, end)
            } else {
                // Armed again while it ran, by another write or by the run's own: the run's
                // outcome is the old arming's, and the new one stands.
                Some(armed_again(spec, row.clone(), end))
            };
            store_row_in_txn(&self.store, txn, key, Some(&row), next.as_ref())
        })?;
        Ok(run)
    }

    /// The checks before a run, and its start marker, in the run's first write: an interrupted
    /// run counts as a failure; a lapsed occurrence is dropped; an agent's arming is judged
    /// again. `Err` names why nothing runs.
    #[allow(clippy::type_complexity)]
    fn start_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        spec: &'static JobSpec,
        key: &[u8],
        row: ScheduleRow,
        due_at: u64,
        now: u64,
    ) -> Result<std::result::Result<(&'static JobSpec, Armed), JobOutcome>> {
        if let Some(started) = row.started_at {
            let failures = row.failures.saturating_add(1);
            let retry = retry_after(
                failures,
                spec.retry_first_secs,
                spec.retry_cap(&row.trigger),
            );
            let next = ScheduleRow {
                started_at: None,
                failures,
                resume_at: Some(started.saturating_add(retry)),
                ..row.clone()
            };
            store_row_in_txn(&self.store, txn, key, Some(&row), Some(&next))?;
            return Ok(Err(JobOutcome::Interrupted));
        }
        if let Late::Lapse { after_secs } = spec.late
            && now.saturating_sub(due_at) > after_secs
            && row.requested_at.is_none_or(|requested| requested > due_at)
        {
            let next = next_occurrence(&row, now).map(|next_due_at| ScheduleRow {
                next_due_at,
                requested_at: None,
                resume_at: None,
                ..row.clone()
            });
            store_row_in_txn(&self.store, txn, key, Some(&row), next.as_ref())?;
            return Ok(Err(JobOutcome::Lapsed));
        }
        if let Some(armed) = row.armed_by
            && !self.arming_stands_in_txn(txn, spec, armed.actor)?
        {
            store_row_in_txn(&self.store, txn, key, Some(&row), None)?;
            return Ok(Err(JobOutcome::Withdrawn));
        }
        let requested = row.answering || row.requested_at.is_some();
        let marked = ScheduleRow {
            started_at: Some(now),
            requested_at: None,
            answering: requested,
            ..row.clone()
        };
        store_row_in_txn(&self.store, txn, key, Some(&row), Some(&marked))?;
        let (_, subject) = parse_row_key(key).unwrap_or_default();
        Ok(Ok((
            spec,
            Armed {
                job: spec.code,
                subject,
                trigger: row.trigger,
                due_at,
                cursor: row.cursor,
                armed_by: row.armed_by.map(|armed| armed.actor),
                requested,
            },
        )))
    }

    /// Whether the agent that armed a job of `spec` still holds the power to, now: its live
    /// Grant listing `vault.schedules.arm`, or the job's class.
    fn arming_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        spec: &JobSpec,
        actor: EntityId,
    ) -> Result<bool> {
        Ok(match spec.arm_by {
            ArmBy::Class(class) => self.engine_controls_grant_in(txn, actor, class)?.is_some(),
            ArmBy::Actor | ArmBy::Engine => crate::authority::principal_standing_in_txn(
                self,
                txn,
                actor,
                EdgeActorClass::Agent,
                ARM_VERB,
            )?
            .is_some_and(|standing| standing.grant.is_some()),
        })
    }
}

/// The occurrence after the one `row` serves, once that one ran or was dropped at `now`: the
/// same occurrence while it is still ahead (a run now, or its retry, came before it); else the
/// trigger's next after `now`, counted from it, so the trigger's grid never moves; `None` once a
/// deadline is served.
fn next_occurrence(row: &ScheduleRow, now: u64) -> Option<u64> {
    if row.next_due_at > now {
        Some(row.next_due_at)
    } else {
        row.trigger.next_due(row.next_due_at, now, &EngineZones)
    }
}

/// The row after a run that ended at `end`, or `None` when the job is done for good.
/// - done: the next occurrence ([`next_occurrence`]): a deadline is done; a repeating job is due
///   at its next occurrence after now, or at the run's `due_by` when that is earlier but never
///   sooner than its first retry after the end, its failures, cursor and answered request
///   cleared;
/// - more: due again at once, going on from its cursor;
/// - items failed: due again after the backoff, its cursor cleared;
/// - failed: due again after the backoff, its cursor kept.
///
/// A run that did not end done leaves the request it answered for the run that goes on. A retry
/// or a resumed run keeps the occurrence it serves (`resume_at`), so neither moves the trigger's
/// grid.
fn finished(spec: &JobSpec, row: ScheduleRow, result: &JobResult, end: u64) -> Option<ScheduleRow> {
    let row = ScheduleRow {
        started_at: None,
        finished_at: end,
        ..row
    };
    match &result.ran {
        Ran::Done => next_occurrence(&row, end).map(|next_due_at| ScheduleRow {
            // A `due_by` already past means soon, never again in this pass.
            next_due_at: result.due_by.map_or(next_due_at, |due_by| {
                due_by
                    .max(end.saturating_add(spec.retry_first_secs))
                    .min(next_due_at)
            }),
            resume_at: None,
            failures: 0,
            cursor: None,
            answering: false,
            ..row
        }),
        Ran::More { cursor } => Some(ScheduleRow {
            resume_at: Some(end),
            cursor: Some(cursor.clone()),
            ..row
        }),
        Ran::ItemsFailed => {
            let failures = row.failures.saturating_add(1);
            let retry = retry_after(
                failures,
                spec.retry_first_secs,
                spec.retry_cap(&row.trigger),
            );
            Some(ScheduleRow {
                resume_at: Some(end.saturating_add(retry)),
                failures,
                cursor: None,
                ..row
            })
        }
        Ran::Failed => {
            let failures = row.failures.saturating_add(1);
            let retry = retry_after(
                failures,
                spec.retry_first_secs,
                spec.retry_cap(&row.trigger),
            );
            Some(ScheduleRow {
                resume_at: Some(end.saturating_add(retry)),
                failures,
                ..row
            })
        }
    }
}

/// A row armed again while a run of its earlier arming ran, after that run ended at `end`: the
/// new arming stands, due no sooner than the run's first retry after its end, so a job that arms
/// itself again at once never runs in a loop. Its occurrence stays where the arming put it, and
/// its last run is the one that ended at `end`.
fn armed_again(spec: &JobSpec, row: ScheduleRow, end: u64) -> ScheduleRow {
    let floor = end.saturating_add(spec.retry_first_secs);
    let row = ScheduleRow {
        finished_at: end,
        ..row
    };
    if row.resume_at.unwrap_or(row.next_due_at) >= floor {
        return row;
    }
    ScheduleRow {
        resume_at: Some(floor),
        ..row
    }
}
