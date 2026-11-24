//! The pure projection behind `vault.jobs.history`: stored jobs, claims and periods in, the
//! ended attempts and their totals out. It reads the claim's terminal exactly as the line's
//! fold does, so its charged seconds are the fold's.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::gpu_job::{GpuChunk, GpuEndReason, GpuJob, GpuJobState};
use crate::gpu_line::{ClaimState, GpuLinePeriod, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal};

use super::{
    JobHistory, JobHistoryAttempt, JobHistoryFamilySum, JobHistoryLineCharge, JobHistoryLineSum,
    JobHistoryMachineSum, JobHistoryOfferCharge, JobHistoryPeriodSum, JobHistorySum,
    JobHistoryTotals,
};

/// The stored rows the projection reads.
#[derive(Debug, Clone, Copy)]
pub struct HistoryInputs<'a> {
    /// Every `GPU_JOB` row.
    pub jobs: &'a [GpuJob],
    /// Every unit claim.
    pub claims: &'a [UnitClaim],
    /// The minted periods the ended claims name (a period with no record shows no window).
    pub periods: &'a [GpuLinePeriod],
}

/// Whose attempts the answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryViewer {
    /// The vault owner: every attempt.
    Owner,
    /// An agent: the attempts this actor started or reserved.
    Requester(EntityId),
}

/// A validated `vault.jobs.history` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobHistoryFilter {
    pub machine: Option<EntityId>,
    pub line: Option<EntityId>,
    pub family: Option<EntityId>,
    pub period: Option<u32>,
    pub limit: usize,
    pub after: Option<HistoryCursor>,
}

/// Where a page ends: the last attempt's place in the order (newest end first, an unknown end
/// last, then by key).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistoryCursor {
    /// `None` first: an attempt with a known end sorts before every one without.
    unknown_end: bool,
    newest_first: std::cmp::Reverse<u64>,
    key: String,
}

impl HistoryCursor {
    fn of(attempt: &JobHistoryAttempt) -> Self {
        Self {
            unknown_end: attempt.ended_at_ms.is_none(),
            newest_first: std::cmp::Reverse(attempt.ended_at_ms.unwrap_or(0)),
            key: attempt.key.clone(),
        }
    }

    /// The cursor `next` spells, or `None` for a string this door did not write.
    #[must_use]
    pub fn parse(cursor: &str) -> Option<Self> {
        let (end, key) = cursor.split_once('/')?;
        if key.is_empty() {
            return None;
        }
        let ended_at_ms = match end {
            "-" => None,
            ms => Some(ms.parse::<u64>().ok()?),
        };
        Some(Self {
            unknown_end: ended_at_ms.is_none(),
            newest_first: std::cmp::Reverse(ended_at_ms.unwrap_or(0)),
            key: key.to_owned(),
        })
    }

    fn spell(&self) -> String {
        let end = if self.unknown_end {
            "-".to_owned()
        } else {
            self.newest_first.0.to_string()
        };
        format!("{end}/{}", self.key)
    }
}

/// The ended attempts of `inputs` that `filter` and `viewer` admit, one page of them, and the
/// totals over all of them.
#[must_use]
pub fn project(
    inputs: &HistoryInputs<'_>,
    filter: &JobHistoryFilter,
    viewer: HistoryViewer,
) -> JobHistory {
    let unit_jobs: BTreeSet<EntityId> = inputs.claims.iter().map(|claim| claim.id).collect();
    let jobs: BTreeMap<EntityId, &GpuJob> = inputs.jobs.iter().map(|job| (job.id, job)).collect();
    let mut attempts: Vec<JobHistoryAttempt> = inputs
        .claims
        .iter()
        .filter_map(|claim| unit_attempt(claim, jobs.get(&claim.id).copied()))
        .chain(
            inputs
                .jobs
                .iter()
                .filter(|job| !unit_jobs.contains(&job.id))
                .flat_map(offer_attempts),
        )
        .filter(|attempt| admitted(attempt, filter, viewer))
        .collect();
    attempts.sort_by_cached_key(HistoryCursor::of);
    let totals = totals(&attempts, inputs.periods);
    let start = filter.after.as_ref().map_or(0, |after| {
        attempts.partition_point(|attempt| HistoryCursor::of(attempt) <= *after)
    });
    let end = start.saturating_add(filter.limit).min(attempts.len());
    let next = (end < attempts.len() && end > start)
        .then(|| HistoryCursor::of(&attempts[end - 1]).spell());
    let page = attempts.drain(start..end).collect();
    JobHistory {
        attempts: page,
        totals,
        next,
    }
}

fn admitted(attempt: &JobHistoryAttempt, filter: &JobHistoryFilter, viewer: HistoryViewer) -> bool {
    let hex = |id: &Option<EntityId>| id.map(|id| id.to_hex());
    if let HistoryViewer::Requester(actor) = viewer
        && attempt.requester.as_deref() != Some(actor.to_hex().as_str())
    {
        return false;
    }
    if let Some(machine) = hex(&filter.machine)
        && attempt.machine.as_deref() != Some(machine.as_str())
    {
        return false;
    }
    let line = attempt.line.as_ref();
    if let Some(wanted) = hex(&filter.line)
        && line.is_none_or(|charge| charge.line != wanted)
    {
        return false;
    }
    if let Some(wanted) = hex(&filter.family)
        && line.is_none_or(|charge| charge.family != wanted)
    {
        return false;
    }
    if let Some(wanted) = filter.period
        && line.is_none_or(|charge| charge.period != wanted)
    {
        return false;
    }
    true
}

/// A line unit's attempt, from its claim's terminal; `None` while the claim is open.
fn unit_attempt(claim: &UnitClaim, job: Option<&GpuJob>) -> Option<JobHistoryAttempt> {
    let ClaimState::Ended(terminal) = &claim.state else {
        return None;
    };
    let chunk = job.and_then(|job| job.chunks.first());
    let (end, end_reason) = unit_end(terminal);
    let occupied_secs = match terminal.end {
        // No machine says what a lost or written-off job occupied.
        UnitEnd::BoxLost | UnitEnd::WrittenOff { .. } => None,
        UnitEnd::Settled | UnitEnd::Released(_) => Some(terminal.measured_secs),
    };
    let machine = terminal
        .machine
        .or(claim.machine)
        .or_else(|| chunk.and_then(quoted_machine));
    Some(JobHistoryAttempt {
        key: chunk.map_or_else(
            || chunk_key(&claim.id, 0),
            |chunk| chunk.idempotency_key.clone(),
        ),
        job: claim.id.to_hex(),
        chunk: 0,
        requester: claim.reserved_by.map(|actor| actor.to_hex()),
        grant: claim.grant.map(|grant| grant.to_hex()),
        workload: Some(claim.workload.clone()),
        line: Some(JobHistoryLineCharge {
            line: claim.line.to_hex(),
            family: claim.family.to_hex(),
            arm: claim.arm.to_hex(),
            rung: claim.rung,
            unit_key: claim.unit_key.clone(),
            attempt: claim.attempt,
            period: claim.period,
            purpose: match claim.purpose {
                UnitPurpose::Work => "work",
                UnitPurpose::ReviewCheck => "review_check",
            }
            .to_owned(),
        }),
        offer: None,
        machine: machine.map(|machine| machine.to_hex()),
        device: terminal.device_id.clone(),
        reserved_at_ms: Some(claim.reserved_at_ms),
        ended_at_ms: Some(terminal.ended_at_ms),
        reserved_secs: claim.reserved_secs,
        occupied_secs,
        billed_secs: chunk.and_then(|chunk| chunk.billed_secs),
        charged_secs: Some(terminal.charged_secs),
        returned_secs: Some(claim.reserved_secs.saturating_sub(terminal.charged_secs)),
        lost_secs: terminal.lost_secs,
        settled_units: None,
        unit: None,
        end: end.to_owned(),
        end_reason,
        node_end: terminal.node_end.clone(),
        continues: None,
    })
}

fn unit_end(terminal: &UnitTerminal) -> (&'static str, Option<String>) {
    match &terminal.end {
        UnitEnd::Settled => ("settled", None),
        UnitEnd::Released(reason) => ("released", Some(reason.clone())),
        UnitEnd::BoxLost => ("box_lost", None),
        UnitEnd::WrittenOff { .. } => ("written_off", None),
    }
}

/// A plain offer job's ended chunks. Every chunk before the last stopped at its maximum (a
/// resume starts only from a stop); the last has ended when the job no longer runs and its
/// end is the job's.
fn offer_attempts(job: &GpuJob) -> Vec<JobHistoryAttempt> {
    let last = job.chunks.len().saturating_sub(1);
    job.chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| {
            let (end, end_reason, ended_at_ms) = if index < last {
                ("at_maximum".to_owned(), None, None)
            } else {
                let (end, reason) = offer_end(&job.state)?;
                (end, reason, Some(job.updated_at_ms))
            };
            Some(JobHistoryAttempt {
                key: chunk.idempotency_key.clone(),
                job: job.id.to_hex(),
                chunk: u32::try_from(index).unwrap_or(u32::MAX),
                requester: job.started_by.map(|actor| actor.to_hex()),
                grant: None,
                workload: None,
                line: None,
                offer: Some(JobHistoryOfferCharge {
                    offer: job.offer.name.clone(),
                    class: job.offer.class.clone(),
                    provider: job.offer.provider.clone(),
                }),
                machine: quoted_machine(chunk).map(|machine| machine.to_hex()),
                device: None,
                reserved_at_ms: (index == 0).then_some(job.created_at_ms),
                ended_at_ms,
                reserved_secs: chunk.quote.quantity,
                occupied_secs: Some(chunk.used_secs),
                billed_secs: chunk.billed_secs,
                charged_secs: None,
                returned_secs: None,
                lost_secs: 0,
                settled_units: chunk.settled_units,
                unit: Some(chunk.quote.unit.as_str().to_owned()),
                end,
                end_reason,
                node_end: None,
                continues: index
                    .checked_sub(1)
                    .map(|before| job.chunks[before].idempotency_key.clone()),
            })
        })
        .collect()
}

/// A job's end, or `None` while it still runs.
fn offer_end(state: &GpuJobState) -> Option<(String, Option<String>)> {
    let reason = |reason: &GpuEndReason| {
        match reason {
            GpuEndReason::Exited => "exited",
            GpuEndReason::AtMaximum => "at_maximum",
            GpuEndReason::Cancelled => "cancelled",
            GpuEndReason::Gone => "gone",
        }
        .to_owned()
    };
    match state {
        GpuJobState::Reserved | GpuJobState::Running | GpuJobState::Ending { .. } => None,
        GpuJobState::Stopped => Some(("at_maximum".to_owned(), None)),
        GpuJobState::Ended { reason: end } => Some((reason(end), None)),
        GpuJobState::Held { reason } => Some(("held".to_owned(), Some(reason.clone()))),
    }
}

/// The machine a chunk's quote fixed (pass 33: the quote's `inputs.machine`, hex).
fn quoted_machine(chunk: &GpuChunk) -> Option<EntityId> {
    chunk
        .quote
        .inputs
        .get("machine")
        .and_then(serde_json::Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
}

/// A job's chunk key, as the job's start writes it.
fn chunk_key(job: &EntityId, index: usize) -> String {
    format!("{}:{index}", job.to_hex())
}

fn add(sum: &mut JobHistorySum, attempt: &JobHistoryAttempt) {
    sum.attempts = sum.attempts.saturating_add(1);
    sum.reserved_secs = sum.reserved_secs.saturating_add(attempt.reserved_secs);
    match attempt.occupied_secs {
        Some(secs) => sum.occupied_secs = sum.occupied_secs.saturating_add(secs),
        None => sum.occupied_unknown = sum.occupied_unknown.saturating_add(1),
    }
    sum.billed_secs = sum
        .billed_secs
        .saturating_add(attempt.billed_secs.unwrap_or(0));
    sum.charged_secs = sum
        .charged_secs
        .saturating_add(attempt.charged_secs.unwrap_or(0));
    sum.returned_secs = sum
        .returned_secs
        .saturating_add(attempt.returned_secs.unwrap_or(0));
    sum.lost_secs = sum.lost_secs.saturating_add(attempt.lost_secs);
}

fn totals(attempts: &[JobHistoryAttempt], periods: &[GpuLinePeriod]) -> JobHistoryTotals {
    let mut all = JobHistorySum::default();
    let mut by_machine: BTreeMap<Option<String>, JobHistorySum> = BTreeMap::new();
    let mut by_line: BTreeMap<String, JobHistorySum> = BTreeMap::new();
    let mut by_family: BTreeMap<(String, String), JobHistorySum> = BTreeMap::new();
    let mut by_period: BTreeMap<(String, u32), JobHistorySum> = BTreeMap::new();
    for attempt in attempts {
        add(&mut all, attempt);
        add(
            by_machine.entry(attempt.machine.clone()).or_default(),
            attempt,
        );
        if let Some(charge) = &attempt.line {
            add(by_line.entry(charge.line.clone()).or_default(), attempt);
            add(
                by_family
                    .entry((charge.line.clone(), charge.family.clone()))
                    .or_default(),
                attempt,
            );
            add(
                by_period
                    .entry((charge.line.clone(), charge.period))
                    .or_default(),
                attempt,
            );
        }
    }
    let window: BTreeMap<(String, u32), (u64, u64)> = periods
        .iter()
        .map(|period| {
            (
                (period.project.to_hex(), period.index),
                (period.start_ms, period.end_ms),
            )
        })
        .collect();
    JobHistoryTotals {
        all,
        by_machine: by_machine
            .into_iter()
            .map(|(machine, sum)| JobHistoryMachineSum { machine, sum })
            .collect(),
        by_line: by_line
            .into_iter()
            .map(|(line, sum)| JobHistoryLineSum { line, sum })
            .collect(),
        by_family: by_family
            .into_iter()
            .map(|((line, family), sum)| JobHistoryFamilySum { line, family, sum })
            .collect(),
        by_period: by_period
            .into_iter()
            .map(|((line, period), sum)| {
                let window = window.get(&(line.clone(), period)).copied();
                JobHistoryPeriodSum {
                    line,
                    period,
                    start_ms: window.map(|(start, _)| start),
                    end_ms: window.map(|(_, end)| end),
                    sum,
                }
            })
            .collect(),
    }
}
