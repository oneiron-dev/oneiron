//! The pure projection behind `vault.jobs.history`: stored jobs, claims, periods, work orders,
//! the issuer's observations and the allocation's unattributed records in, the ended attempts
//! and their totals out. It reads the claim's terminal exactly as the line's fold does, so its
//! charged seconds are the fold's.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::gpu_job::{GpuEndReason, GpuJob, GpuJobEnd, GpuJobState, MeterVerdict};
use crate::gpu_line::{
    ClaimState, GpuLinePeriod, UnattributedRecord, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal,
};
use crate::job_dispatch::JobObservation;
use crate::work_order::{OrderAttempt, WorkOrder};

use super::{
    JobHistory, JobHistoryAttempt, JobHistoryFamilySum, JobHistoryLineCharge, JobHistoryLineSum,
    JobHistoryMachineSum, JobHistoryOfferCharge, JobHistoryOrder, JobHistoryPeriodSum,
    JobHistorySum, JobHistoryTotals,
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
    /// Every work order: each attempt entry names the job it made.
    pub orders: &'a [WorkOrder],
    /// The issuer's observation of each attempt key a vault machine answered for
    /// (`JOB_OBSERVATION`, pass 33 5.1), in any order.
    pub observations: &'a [JobObservation],
    /// Every machine's answer that lists jobs no row of the vault names (`GPU_ALLOCATION_NODE`,
    /// pass 33 8.5, EM-15), in any order.
    pub unattributed: &'a [UnattributedRecord],
}

/// Whose attempts the answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryViewer {
    /// The vault owner: every attempt.
    Owner,
    /// An agent: the line units this actor reserved and the first chunks of the offer jobs it
    /// started (a resumed chunk's starter is not stored).
    Requester(EntityId),
}

/// A validated `vault.jobs.history` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobHistoryFilter {
    pub machine: Option<EntityId>,
    pub line: Option<EntityId>,
    pub family: Option<EntityId>,
    pub period: Option<u32>,
    pub order: Option<EntityId>,
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
    let ordered = OrderIndex::of(inputs.orders);
    let observed: BTreeMap<&str, &JobObservation> = inputs
        .observations
        .iter()
        .map(|observation| (observation.key.as_str(), observation))
        .collect();
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
        .map(|mut attempt| {
            if let Some(observation) = observed.get(attempt.key.as_str()) {
                observe(&mut attempt, observation);
            }
            attempt.order = ordered.order_of(&attempt, viewer);
            attempt
        })
        .filter(|attempt| admitted(attempt, filter, viewer))
        .collect();
    attempts.sort_by_cached_key(HistoryCursor::of);
    let unattributed = unattributed_of(inputs.unattributed, filter, viewer);
    let totals = totals(&attempts, &unattributed, inputs.periods);
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
    if let Some(wanted) = hex(&filter.order)
        && attempt
            .order
            .as_ref()
            .is_none_or(|order| order.order != wanted)
    {
        return false;
    }
    true
}

/// One attempt entry of a work order, with the entry before it.
#[derive(Debug, Clone, Copy)]
struct OrderedAttempt<'a> {
    order: &'a WorkOrder,
    attempt: &'a OrderAttempt,
    /// The attempt before it, whose end opened the order again.
    before: Option<&'a OrderAttempt>,
}

/// The work orders' attempt entries by the hex of the job each made.
struct OrderIndex<'a>(BTreeMap<String, OrderedAttempt<'a>>);

impl<'a> OrderIndex<'a> {
    fn of(orders: &'a [WorkOrder]) -> Self {
        let mut by_job = BTreeMap::new();
        for order in orders {
            let mut before = None;
            for attempt in &order.attempts {
                by_job.insert(
                    attempt.job.to_hex(),
                    OrderedAttempt {
                        order,
                        attempt,
                        before,
                    },
                );
                before = Some(attempt);
            }
        }
        Self(by_job)
    }

    /// The work order `attempt` was made for, as `viewer` reads it. An order's attempt is its
    /// job's first chunk: a later chunk is a resume, which no order makes.
    fn order_of(
        &self,
        attempt: &JobHistoryAttempt,
        viewer: HistoryViewer,
    ) -> Option<JobHistoryOrder> {
        if attempt.chunk != 0 {
            return None;
        }
        let OrderedAttempt {
            order,
            attempt: made,
            before,
        } = *self.0.get(&attempt.job)?;
        let queued_from_ms = match before {
            None => Some(order.ordered_at_ms),
            Some(before) => before.end.as_ref().map(|end| end.at_ms),
        };
        let own = order.id.to_hex();
        let mut ranked = made.ranked.clone();
        // The orders runnable in that pass may be other callers': an agent sees only its own.
        if matches!(viewer, HistoryViewer::Requester(_)) {
            ranked.options.retain(|option| *option == own);
        }
        Some(JobHistoryOrder {
            order: own,
            attempt: made.n,
            ordered_by: order.ordered_by.clone(),
            class: order.class,
            ordered_at_ms: order.ordered_at_ms,
            made_at_ms: made.made_at_ms,
            queued_ms: queued_from_ms.map(|from| made.made_at_ms.saturating_sub(from)),
            started_at_ms: made.started_at_ms,
            machine: made.machine.map(|machine| machine.to_hex()),
            ranked,
            placed: made.placed.clone(),
            end: made.end.clone(),
        })
    }
}

/// What the issuer's observation of an attempt's key adds (pass 33, 5.1). Every attempt whose
/// end the issuer confirmed shows how its billed seconds were found. A plain offer chunk's job
/// row names no machine and keeps no end time, so for a chunk a vault machine ran the
/// observation names the machine that answered and its device, and its confirmed end gives the
/// machine's end cause, when the issuer received it, the seconds the machine measured (0 for a
/// run that never started) and a lost key's last seen run time. A line unit's claim terminal
/// already holds those, from the same receipt, as the line's fold charged it.
fn observe(attempt: &mut JobHistoryAttempt, observation: &JobObservation) {
    let terminal = observation.terminal.as_ref();
    attempt.meter = terminal.map(|terminal| meter_label(terminal.meter));
    if attempt.line.is_some() {
        return;
    }
    let machine = terminal
        .and_then(|terminal| terminal.machine)
        .unwrap_or(observation.machine);
    attempt.machine = Some(machine.to_hex());
    attempt.device = terminal
        .and_then(|terminal| terminal.device_id.clone())
        .or_else(|| observation.device_id.clone());
    let Some(terminal) = terminal else {
        return;
    };
    attempt.node_end = Some(terminal.end.label());
    attempt.ended_at_ms = observation.end_seen.as_ref().map(|seen| seen.wall_ms);
    attempt.occupied_secs = if terminal.end.never_ran() {
        Some(0)
    } else {
        terminal.measured_secs
    };
    attempt.lost_secs = if let GpuJobEnd::Lost { last_seen_secs, .. } = terminal.end {
        last_seen_secs
    } else {
        0
    };
}

/// The meter verdict as views show it: `agreed`, `bracketed` or `unknown`.
fn meter_label(meter: MeterVerdict) -> String {
    match meter {
        MeterVerdict::Agreed => "agreed",
        MeterVerdict::Bracketed { .. } => "bracketed",
        MeterVerdict::Unknown => "unknown",
    }
    .to_owned()
}

/// The key of every attempt `jobs` and `claims` can list: each chunk's, and a claim's first
/// chunk key where its job row is gone. History reads each key's observation by it.
pub(super) fn attempt_keys(jobs: &[GpuJob], claims: &[UnitClaim]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for job in jobs {
        for chunk in &job.chunks {
            keys.insert(chunk.idempotency_key.clone());
        }
    }
    for claim in claims {
        keys.insert(chunk_key(&claim.id, 0));
    }
    keys
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
    // The machine that answered for the run, never the pin the reservation asked for.
    let machine = terminal.machine;
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
        meter: None,
        charged_secs: Some(terminal.charged_secs),
        returned_secs: Some(claim.reserved_secs.saturating_sub(terminal.charged_secs)),
        lost_secs: terminal.lost_secs,
        settled_units: None,
        unit: None,
        end: end.to_owned(),
        end_reason,
        node_end: terminal.node_end.clone(),
        continues: None,
        order: None,
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

/// How an offer chunk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OfferEnd {
    Exited,
    AtMaximum,
    Cancelled,
    Gone,
    /// The owner wrote the job off (door 10): its end was never confirmed, and its chunk
    /// settled zero where this host held the chunk's permit.
    WrittenOff,
    /// The backend ended the chunk at its maximum seconds (pass 33, 8.6), and reported its run
    /// time with the end, as with an exit: never `AtMaximum`, whose stop offers a resume.
    TimeLimit,
    /// The machine refused or withdrew the chunk before it ran.
    NeverStarted,
    /// Refused before any resource existed: nothing ran and nothing was charged.
    Held(String),
}

impl OfferEnd {
    fn of(reason: GpuEndReason) -> Self {
        match reason {
            GpuEndReason::Exited => Self::Exited,
            GpuEndReason::AtMaximum => Self::AtMaximum,
            GpuEndReason::Cancelled => Self::Cancelled,
            GpuEndReason::Gone => Self::Gone,
            GpuEndReason::Unconfirmed => Self::WrittenOff,
            GpuEndReason::TimeLimit => Self::TimeLimit,
            GpuEndReason::NeverStarted => Self::NeverStarted,
        }
    }

    /// The last chunk's end, or `None` while the job still runs. A cancel of a stopped job
    /// gives up its resume and leaves its maximum stopped; the chunk had ended at its maximum.
    fn last(job: &GpuJob) -> Option<Self> {
        match &job.state {
            GpuJobState::Reserved | GpuJobState::Running | GpuJobState::Ending { .. } => None,
            GpuJobState::Stopped => Some(Self::AtMaximum),
            GpuJobState::Ended {
                reason: GpuEndReason::Cancelled,
            } if job.maximum.is_stopped() => Some(Self::AtMaximum),
            GpuJobState::Ended { reason } => Some(Self::of(*reason)),
            GpuJobState::Held { reason } => Some(Self::Held(reason.clone())),
        }
    }

    fn spell(&self) -> (String, Option<String>) {
        let end = match self {
            Self::Exited => "exited",
            Self::AtMaximum => "at_maximum",
            Self::Cancelled => "cancelled",
            Self::Gone => "gone",
            Self::WrittenOff => "written_off",
            Self::TimeLimit => "time_limit",
            Self::NeverStarted => "never_started",
            Self::Held(reason) => return ("held".to_owned(), Some(reason.clone())),
        };
        (end.to_owned(), None)
    }
}

/// A plain offer job's ended chunks. Every chunk before the last stopped at its maximum (a
/// resume starts only from a stop); the last has ended when the job no longer runs, and its end
/// is the job's, except that a stopped job the customer cancelled keeps its `at_maximum`. The
/// row keeps no chunk's own end time (the job's last write moves at every later write, a resume
/// or a cancel) and names no machine (an offer's inputs are the customer's, not a placement); a
/// chunk a vault machine ran takes both from the issuer's observation of its key ([`observe`]).
/// Only the first chunk names its starter: a resume's is not stored
/// (an agent resumes only its own job, the owner any). The run time a chunk last reported is
/// final only for an exit or a time limit, which the provider reports with it; a stop or a
/// cancel terminates after the last report, so its occupancy is unknown, and a lost resource's
/// is a lower bound, shown as lost. A held or never-started chunk occupied zero seconds, charged
/// nothing and returned its whole quote. A chunk the owner wrote off has no confirmed end:
/// its occupancy is unknown, and it charged what its settlement says (zero where this host held
/// its permit).
fn offer_attempts(job: &GpuJob) -> Vec<JobHistoryAttempt> {
    let last = job.chunks.len().saturating_sub(1);
    job.chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| {
            let end = if index < last {
                OfferEnd::AtMaximum
            } else {
                OfferEnd::last(job)?
            };
            let never_ran = matches!(end, OfferEnd::Held(_) | OfferEnd::NeverStarted);
            // The settled units are the charged seconds times the quote's price of one second.
            let charged_secs = if never_ran {
                Some(0)
            } else {
                chunk
                    .settled_units
                    .zip((chunk.quote.unit_cost > 0).then_some(chunk.quote.unit_cost))
                    .map(|(units, cost)| units / cost)
            };
            let occupied_secs = match end {
                OfferEnd::Exited | OfferEnd::TimeLimit => Some(chunk.used_secs),
                OfferEnd::Held(_) | OfferEnd::NeverStarted => Some(0),
                OfferEnd::AtMaximum
                | OfferEnd::Cancelled
                | OfferEnd::Gone
                | OfferEnd::WrittenOff => None,
            };
            let lost_secs = if end == OfferEnd::Gone {
                chunk.used_secs
            } else {
                0
            };
            let (end, end_reason) = end.spell();
            Some(JobHistoryAttempt {
                key: chunk.idempotency_key.clone(),
                job: job.id.to_hex(),
                chunk: u32::try_from(index).unwrap_or(u32::MAX),
                requester: if index == 0 {
                    job.started_by.map(|actor| actor.to_hex())
                } else {
                    None
                },
                grant: None,
                workload: None,
                line: None,
                offer: Some(JobHistoryOfferCharge {
                    offer: job.offer.name.clone(),
                    class: job.offer.class.clone(),
                    provider: job.offer.provider.clone(),
                }),
                machine: None,
                device: None,
                reserved_at_ms: (index == 0).then_some(job.created_at_ms),
                ended_at_ms: None,
                reserved_secs: chunk.quote.quantity,
                occupied_secs,
                billed_secs: chunk.billed_secs,
                meter: None,
                charged_secs,
                returned_secs: charged_secs
                    .map(|charged| chunk.quote.quantity.saturating_sub(charged)),
                lost_secs,
                settled_units: chunk.settled_units,
                unit: Some(chunk.quote.unit.as_str().to_owned()),
                end,
                end_reason,
                node_end: None,
                continues: index
                    .checked_sub(1)
                    .map(|before| job.chunks[before].idempotency_key.clone()),
                order: None,
            })
        })
        .collect()
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
    if let Some(queued) = attempt.order.as_ref().and_then(|order| order.queued_ms) {
        sum.queued_ms = sum.queued_ms.saturating_add(queued);
        sum.queued_attempts = sum.queued_attempts.saturating_add(1);
    }
}

/// One unattributed job, as the totals place it.
struct Unattributed {
    machine: String,
    /// The line and the period, for a line's generation.
    place: Option<(String, u32)>,
    secs: u64,
    ended: bool,
}

/// The unattributed jobs (pass 33 8.5, EM-15) `filter` admits, for the owner only: no row names
/// who started them, and the design gives them to the owner. They belong to no family and to no
/// work order, so a family or an order filter admits none, and a line or a period filter admits
/// only a line's generation it names.
fn unattributed_of(
    records: &[UnattributedRecord],
    filter: &JobHistoryFilter,
    viewer: HistoryViewer,
) -> Vec<Unattributed> {
    if viewer != HistoryViewer::Owner || filter.family.is_some() || filter.order.is_some() {
        return Vec::new();
    }
    let mut admitted = Vec::new();
    for record in records {
        if let Some(machine) = filter.machine
            && machine != record.machine
        {
            continue;
        }
        let place = record.line_period();
        if let Some(line) = filter.line
            && place.is_none_or(|(at, _)| at != line)
        {
            continue;
        }
        if let Some(period) = filter.period
            && place.is_none_or(|(_, at)| at != period)
        {
            continue;
        }
        let place = place.map(|(line, period)| (line.to_hex(), period));
        for job in &record.jobs {
            admitted.push(Unattributed {
                machine: record.machine.to_hex(),
                place: place.clone(),
                secs: job.secs,
                ended: job.ended,
            });
        }
    }
    admitted
}

fn add_unattributed(sum: &mut JobHistorySum, job: &Unattributed) {
    sum.unattributed_secs = sum.unattributed_secs.saturating_add(job.secs);
    if !job.ended {
        sum.unattributed_running = sum.unattributed_running.saturating_add(1);
    }
}

fn totals(
    attempts: &[JobHistoryAttempt],
    unattributed: &[Unattributed],
    periods: &[GpuLinePeriod],
) -> JobHistoryTotals {
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
    for job in unattributed {
        add_unattributed(&mut all, job);
        add_unattributed(
            by_machine.entry(Some(job.machine.clone())).or_default(),
            job,
        );
        if let Some((line, period)) = &job.place {
            add_unattributed(by_line.entry(line.clone()).or_default(), job);
            add_unattributed(by_period.entry((line.clone(), *period)).or_default(), job);
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
