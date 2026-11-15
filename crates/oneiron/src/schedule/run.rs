//! The one runner: every armed job that is due, in due order, within the pass's budget.

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};

use super::arm::{ARM_VERB, DUE, ROWS, ScheduleRow, due_key, parse_row_key, store_row_in_txn};
use super::{ArmBy, Armed, EngineZones, JobSpec, Late, Ran, job_named, retry_after};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::housekeeping_schedule::{Deadline, HousekeepingBudget};

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
}

/// What became of one due job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum JobOutcome {
    /// It ran to the end of its work.
    Done,
    /// It stopped at its budget and is due again at once.
    More,
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
        self.run_due_until(&budget.deadline())
    }

    /// [`Self::run_due`] until `deadline`.
    pub(crate) fn run_due_until(&self, deadline: &Deadline) -> Result<ScheduleRunReport> {
        let _pass = self
            .housekeeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut report = ScheduleRunReport::default();
        while report.runs.len() < RUNS_PER_PASS && !deadline.passed() {
            let now = self.now_recorded_at();
            let due = {
                let txn = self.store.env.read_txn()?;
                first_due_in_txn(self, &txn, now)?
            };
            let Some((due_at, key)) = due else {
                break;
            };
            report.runs.push(self.run_one(&key, due_at, deadline)?);
        }
        Ok(report)
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
    /// another.
    fn run_one(&self, key: &[u8], due_at: u64, deadline: &Deadline) -> Result<JobRun> {
        let (job, subject) = parse_row_key(key).unwrap_or_default();
        let mut run = JobRun {
            job: job.clone(),
            subject: subject.map(|subject| subject.to_hex()),
            due_at,
            outcome: JobOutcome::Done,
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
                    // Parked until a build that knows the job: out of the due order for a day.
                    let parked = ScheduleRow {
                        next_due_at: now.saturating_add(24 * 60 * 60),
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
        let ran = catch_unwind(AssertUnwindSafe(|| (spec.run)(self, &armed, deadline)));
        run.outcome = match &ran {
            Ok(Ok(Ran::Done)) => JobOutcome::Done,
            Ok(Ok(Ran::More { .. })) => JobOutcome::More,
            Ok(Ok(Ran::Failed)) => JobOutcome::Failed {
                error: "the job reported a failure".to_owned(),
            },
            Ok(Err(error)) => JobOutcome::Failed {
                error: error.to_string(),
            },
            Err(_) => JobOutcome::Panicked,
        };
        let ran = match ran {
            Ok(Ok(ran)) => ran,
            Ok(Err(_)) | Err(_) => Ran::Failed,
        };
        self.with_write_txn_grouped(|txn| {
            let Some(row) = ROWS.get(&self.store, txn, &key.to_vec())? else {
                // Disarmed while it ran.
                return Ok(());
            };
            let end = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let next = finished(spec, row.clone(), &ran, due_at, end);
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
                next_due_at: started.saturating_add(retry),
                ..row.clone()
            };
            store_row_in_txn(&self.store, txn, key, Some(&row), Some(&next))?;
            return Ok(Err(JobOutcome::Interrupted));
        }
        if let Late::Lapse { after_secs } = spec.late
            && now.saturating_sub(due_at) > after_secs
            && row.requested_at.is_none_or(|requested| requested > due_at)
        {
            let next = row
                .trigger
                .next_due(due_at, now, &EngineZones)
                .map(|next_due_at| ScheduleRow {
                    next_due_at,
                    requested_at: None,
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
        let marked = ScheduleRow {
            started_at: Some(now),
            requested_at: None,
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

/// The row after a run that ended at `end`, or `None` when the job is done for good.
/// - done: a deadline is done; a repeating job is next due at its next occurrence after now, its
///   failures and cursor cleared;
/// - more: due again at once, going on from its cursor;
/// - failed: due again after the backoff, its cursor kept.
fn finished(
    spec: &JobSpec,
    row: ScheduleRow,
    ran: &Ran,
    due_at: u64,
    end: u64,
) -> Option<ScheduleRow> {
    let row = ScheduleRow {
        started_at: None,
        finished_at: end,
        ..row
    };
    match ran {
        Ran::Done => row
            .trigger
            .next_due(due_at, end, &EngineZones)
            .map(|next_due_at| ScheduleRow {
                next_due_at,
                failures: 0,
                cursor: None,
                ..row
            }),
        Ran::More { cursor } => Some(ScheduleRow {
            next_due_at: end,
            cursor: Some(cursor.clone()),
            ..row
        }),
        Ran::Failed => {
            let failures = row.failures.saturating_add(1);
            let retry = retry_after(
                failures,
                spec.retry_first_secs,
                spec.retry_cap(&row.trigger),
            );
            Some(ScheduleRow {
                next_due_at: end.saturating_add(retry),
                failures,
                ..row
            })
        }
    }
}
