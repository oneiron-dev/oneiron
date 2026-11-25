//! `vault.jobs.history` (design pass 34 section 5 and row Q2; the scheduler comparison's gap
//! 2, "one view of jobs, nodes and history"): the ended attempts and their totals by machine,
//! family, line and the line's period.
//!
//! It is a view over rows the vault already keeps, as the payoff table is a view over team
//! receipts: no table of its own and no second ledger. An attempt is one chunk of a
//! `GPU_JOB` row. A line unit's job is its `EXPERIMENT_ARM_UNIT` claim's job (the claim's id is
//! the job's id), and the claim's terminal is what the line's own fold charges
//! ([`crate::gpu_line::UnitClaim::spend_row`]), so history reads its charged, measured and
//! lost seconds from there and the job row adds only what the claim does not keep. A plain
//! offer's chunk reads its own quote, run time and settled units. An attempt that has not
//! ended is not history: the open work is `vault.jobs.orders.list`'s.
//!
//! The caller is the vault owner under their own proof, who reads every attempt, or an agent
//! whose own live Grant lists the verb ([`crate::memory::verb_grant_caller`]), who reads the
//! line units it reserved and the first chunks of the offer jobs it started, and totals over
//! those. The caller is judged in the snapshot the answer is read from.
//!
//! An attempt a work order made (pass 34, 1.1) names its order: the order's attempt `n` is the
//! job [`crate::work_order::attempt_job_id`] fixes, so the join is by the job's id, read in the
//! same snapshot. It shows the attempt's number, who ordered, how long the order waited for the
//! attempt, and what the RANK, PLACE and AFTER slots decided, as the order's row keeps them.
//!
//! A chunk one of the vault's machines ran has the issuer's observation of its key
//! (`JOB_OBSERVATION`, pass 33 5.1): the newest receipt the machine signed, read in the same
//! snapshot. Its confirmed end gives how the billed seconds were found (the meter), and for a
//! plain offer chunk, whose job row names no machine and keeps no end time, also the machine
//! that answered, its device, the machine's end cause, when the issuer received it, the seconds
//! the machine measured and a lost key's last seen run time.
//!
//! A machine that ran jobs for this vault that no row of it names (an issuer restored from an
//! older backup, pass 33 8.5 and EM-15) has their seconds recorded against the allocation
//! generation their submit named, as unattributed (`GPU_ALLOCATION_NODE`). The totals show
//! them on their own sum fields: by machine and, for a line's generation, by line and period,
//! never by family, since no family pays them. Only the owner reads them: no row names who
//! started those jobs.
//!
//! What the rows do not keep, history does not invent: a plain offer chunk on a provider has no
//! end time and no machine of its own, a resumed chunk's starter is not stored (the job's
//! starter or the owner), and an occupancy is known only where a machine measured it or a
//! provider reported a chunk's final run time; a lost machine's or a lost resource's occupancy
//! is unknown, never zero.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::gpu_line::{UnitClaim, claims_in_txn, stored_period_in_txn, unattributed_in_txn};
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};
use crate::work_order::{AttemptEnd, OrderClass, OrderedBy, SlotDecision};

mod project;

pub use project::{HistoryCursor, HistoryInputs, HistoryViewer, JobHistoryFilter, project};

/// The verb's registered name.
pub const JOB_HISTORY_VERB: &str = "vault.jobs.history";

/// The attempts one answer lists when the request names no `limit`.
pub const JOB_HISTORY_PAGE: usize = 100;

/// The most attempts one answer lists.
pub const JOB_HISTORY_PAGE_MAX: usize = 1_000;

/// `vault.jobs.history`'s input. Every filter is optional; together they narrow. The totals
/// cover every attempt the filters and the caller admit, not only the page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobHistoryRequest {
    /// Only attempts on this machine (its MACHINE id, hex).
    #[serde(default)]
    pub machine: Option<String>,
    /// Only line units of this line (the lane project's id, hex).
    #[serde(default)]
    pub line: Option<String>,
    /// Only line units of this family (its project id, hex).
    #[serde(default)]
    pub family: Option<String>,
    /// Only line units of this period of their line.
    #[serde(default)]
    pub period: Option<u32>,
    /// Only the attempts of this work order (its id, hex).
    #[serde(default)]
    pub order: Option<String>,
    /// The most attempts to list, newest end first: 100 when absent, at most 1,000.
    #[serde(default)]
    pub limit: Option<u32>,
    /// The `next` of the answer before: the list goes on after it.
    #[serde(default)]
    pub after: Option<String>,
}

impl JobHistoryRequest {
    /// The request as the projection reads it.
    ///
    /// # Errors
    ///
    /// Why a field is not what it says (an id that is not hex, a cursor this door did not
    /// write).
    pub fn filter(&self) -> Result<JobHistoryFilter, String> {
        let id = |field: &str, value: &Option<String>| {
            value
                .as_deref()
                .map(|hex| {
                    EntityId::from_hex(hex)
                        .map_err(|_| format!("the history's {field} is an entity id, hex"))
                })
                .transpose()
        };
        let limit = match self.limit {
            None => JOB_HISTORY_PAGE,
            Some(0) => return Err("the history's limit is at least 1".to_owned()),
            Some(limit) => usize::try_from(limit)
                .unwrap_or(JOB_HISTORY_PAGE_MAX)
                .min(JOB_HISTORY_PAGE_MAX),
        };
        Ok(JobHistoryFilter {
            machine: id("machine", &self.machine)?,
            line: id("line", &self.line)?,
            family: id("family", &self.family)?,
            period: self.period,
            order: id("order", &self.order)?,
            limit,
            after: self
                .after
                .as_deref()
                .map(|cursor| {
                    HistoryCursor::parse(cursor).ok_or_else(|| {
                        "the history's after is a next this door answered".to_owned()
                    })
                })
                .transpose()?,
        })
    }
}

/// `vault.jobs.history`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistory {
    /// The page: ended attempts, newest end first; attempts whose end time no row keeps come
    /// last.
    pub attempts: Vec<JobHistoryAttempt>,
    pub totals: JobHistoryTotals,
    /// The cursor of the next page; absent on the last one.
    pub next: Option<String>,
}

/// One ended attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryAttempt {
    /// The attempt's key: its chunk's idempotency key.
    pub key: String,
    /// The job (hex) and the chunk's index in it.
    pub job: String,
    pub chunk: u32,
    /// Who reserved the line unit, or who started the offer job's first chunk (an actor id,
    /// hex); absent after their erase, and for a resumed chunk, whose starter no row keeps (the
    /// job's starter or the owner), so only the owner reads a resumed chunk.
    pub requester: Option<String>,
    /// The Grant it was reserved under (hex), where the row keeps it; absent for the owner.
    pub grant: Option<String>,
    /// The approved workload's digest, where the row keeps it.
    pub workload: Option<String>,
    /// Exactly one of `line` and `offer`: what the attempt was charged to.
    pub line: Option<JobHistoryLineCharge>,
    pub offer: Option<JobHistoryOfferCharge>,
    /// The machine that answered for the run (hex), and the device it held; absent where no
    /// row names them.
    pub machine: Option<String>,
    pub device: Option<String>,
    /// When it was reserved, on the vault's clock, where a row keeps it.
    pub reserved_at_ms: Option<u64>,
    /// When its end was written, where a row keeps it; for a chunk a vault machine ran, when the
    /// issuer received the machine's end.
    pub ended_at_ms: Option<u64>,
    /// The seconds it held: the reservation, or the chunk's quote.
    pub reserved_secs: u64,
    /// The machine's occupied seconds, as it measured them (0 for a run that never started); for
    /// an offer chunk on a provider, the final run time, known only from the exit it reported
    /// (and 0 for a chunk held before anything ran); absent when unknown, as for a lost machine,
    /// or a provider's stop, cancel or lost resource, whose last reported run time is only a
    /// sample.
    pub occupied_secs: Option<u64>,
    /// The seconds billed, where a row keeps them.
    pub billed_secs: Option<u64>,
    /// How the billed seconds were found, where the issuer confirmed a vault machine's end:
    /// `agreed` (the machine's measured seconds lie inside the issuer's own bracket),
    /// `bracketed` (they were above it, so the bracket was billed) or `unknown` (no measured
    /// seconds: a lost machine, billed 0).
    pub meter: Option<String>,
    /// The seconds charged: for a line unit what the line's pools paid (`min(billed,
    /// reserved)` for a run that ended, else 0); for an offer chunk its settled units over its
    /// quote's price of one second. Absent where no settlement is recorded.
    pub charged_secs: Option<u64>,
    /// What went back: the reservation less the charge (the whole quote for a chunk held
    /// before anything ran).
    pub returned_secs: Option<u64>,
    /// For a lost machine, the run time last seen (a lower bound); else 0.
    pub lost_secs: u64,
    /// What an offer chunk was billed, in its quote's `unit`.
    pub settled_units: Option<u64>,
    pub unit: Option<String>,
    /// How it ended: `settled`, `released`, `box_lost` or `written_off` for a line unit;
    /// `exited`, `time_limit`, `at_maximum`, `cancelled`, `gone`, `written_off` or `held` for an
    /// offer chunk (a chunk that stopped at its maximum stays `at_maximum` when the customer
    /// cancels the stopped job; `time_limit` is a backend's hard stop at the maximum, with no
    /// resume).
    pub end: String,
    /// Why it was released or held, where a row says.
    pub end_reason: Option<String>,
    /// The machine's own end cause (`exited(0)`, `time_limit`, ...), where one answered.
    pub node_end: Option<String>,
    /// The key of the attempt this one resumes (the chunk before, from its checkpoint).
    pub continues: Option<String>,
    /// The work order the attempt was made for, where one was.
    pub order: Option<JobHistoryOrder>,
}

/// A line unit's charge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryLineCharge {
    pub line: String,
    pub family: String,
    pub arm: String,
    pub rung: u8,
    pub unit_key: String,
    pub attempt: u16,
    pub period: u32,
    /// `work` or `review_check`.
    pub purpose: String,
}

/// A plain offer chunk's charge: the offer the customer bought.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryOfferCharge {
    pub offer: String,
    pub class: String,
    pub provider: String,
}

/// The work order an attempt was made for (pass 34, 1.1), as the order's row keeps the attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryOrder {
    /// The order (hex) and the attempt's number in it, from 1.
    pub order: String,
    pub attempt: u16,
    /// Who ordered: the authority the attempt ran under.
    pub ordered_by: OrderedBy,
    pub class: OrderClass,
    pub ordered_at_ms: u64,
    /// When the attempt was made, on the vault's clock.
    pub made_at_ms: u64,
    /// How long the order waited for this attempt: from its order time for the first attempt,
    /// from the end of the attempt before for a later one, to when it was made. Absent when the
    /// attempt before has no recorded end.
    pub queued_ms: Option<u64>,
    /// When the loop first saw the machine's word that the workload ran; absent when no pass
    /// saw it run.
    pub started_at_ms: Option<u64>,
    /// The machine the PLACE rule chose (hex); the attempt's own `machine` is the one that
    /// answered for the run, where a row names it.
    pub machine: Option<String>,
    /// Why the order went first among the runnable ones (RANK) and why on that machine
    /// (PLACE). The RANK options are the orders runnable in that pass: an agent sees only its
    /// own order among them, as `vault.jobs.orders.get` shows it.
    pub ranked: SlotDecision,
    pub placed: SlotDecision,
    /// The end the loop settled for the attempt and the AFTER rule's decision on it; absent
    /// until a pass has read the job's end.
    pub end: Option<AttemptEnd>,
}

/// The seconds of a set of ended attempts. Sums count the known figures; `occupied_unknown`
/// counts the attempts whose occupancy no row knows. The unattributed seconds are no attempt's
/// and enter no other figure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistorySum {
    pub attempts: u32,
    pub reserved_secs: u64,
    pub occupied_secs: u64,
    pub occupied_unknown: u32,
    pub billed_secs: u64,
    pub charged_secs: u64,
    pub returned_secs: u64,
    pub lost_secs: u64,
    /// The milliseconds the work orders waited for their attempts, summed over the
    /// `queued_attempts` attempts whose wait the order's row keeps.
    pub queued_ms: u64,
    pub queued_attempts: u32,
    /// The device seconds machines ran for this vault on jobs no row of the vault names, as the
    /// allocation records them (pass 33 8.5, EM-15): no family pays them, and only the owner
    /// sees them.
    pub unattributed_secs: u64,
    /// The unattributed jobs whose machine holds no terminal receipt yet: their seconds can
    /// still grow.
    pub unattributed_running: u32,
}

/// Totals of one machine; `machine` absent for the attempts no row places.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryMachineSum {
    pub machine: Option<String>,
    pub sum: JobHistorySum,
}

/// Totals of one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryLineSum {
    pub line: String,
    pub sum: JobHistorySum,
}

/// Totals of one family of one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryFamilySum {
    pub line: String,
    pub family: String,
    pub sum: JobHistorySum,
}

/// Totals of one period of one line, with the period's window where its record is minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryPeriodSum {
    pub line: String,
    pub period: u32,
    pub start_ms: Option<u64>,
    /// Exclusive.
    pub end_ms: Option<u64>,
    pub sum: JobHistorySum,
}

/// The totals of every attempt the filters and the caller admit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryTotals {
    pub all: JobHistorySum,
    pub by_machine: Vec<JobHistoryMachineSum>,
    pub by_line: Vec<JobHistoryLineSum>,
    pub by_family: Vec<JobHistoryFamilySum>,
    pub by_period: Vec<JobHistoryPeriodSum>,
}

/// `vault.jobs.history` for `owner`, else this handle's agent under its own Grant.
///
/// # Errors
///
/// `FORBIDDEN` for a caller the verb does not admit; `BAD_REQUEST` for a malformed filter or
/// cursor; a store read failure.
pub fn job_history_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &JobHistoryRequest,
) -> MemoryResult<JobHistory> {
    let vault = memory.vault();
    // One snapshot judges the caller and holds the rows it reads: an attempt that ended after
    // the caller's Grant was revoked is in no snapshot that admits the caller.
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let viewer = match memory.verb_grant_caller_admits_in_txn(&txn, owner, JOB_HISTORY_VERB)? {
        VerbGrantCaller::Owner => HistoryViewer::Owner,
        VerbGrantCaller::Agent { actor, .. } => HistoryViewer::Requester(actor),
    };
    let filter = input
        .filter()
        .map_err(|why| MemoryError::new(MEMORY_CODE_BAD_REQUEST, why, &[]))?;
    Ok(read_job_history_in_txn(vault, &txn, &filter, viewer)?)
}

/// `vault.jobs.history` on a bound handle: the embedded owner reads under its own proof, any
/// other caller under its own Grant.
///
/// # Errors
///
/// As [`job_history_as`].
pub fn job_history_embedded(
    memory: &Memory<'_>,
    input: &JobHistoryRequest,
) -> MemoryResult<JobHistory> {
    let owner = memory.embedded_owner(JOB_HISTORY_VERB).ok();
    job_history_as(memory, owner.as_ref(), input)
}

/// Reads the rows history projects, the jobs, the claims, their periods, the work orders, the
/// issuer's observations of their attempt keys and the allocation's unattributed records, in one
/// snapshot (a claim's terminal and its job's terminal row are one write, and an order's attempt
/// entry is written with its job), and projects them.
///
/// # Errors
///
/// A store read failure.
pub fn read_job_history(
    vault: &Vault,
    filter: &JobHistoryFilter,
    viewer: HistoryViewer,
) -> crate::Result<JobHistory> {
    let txn = vault.store.env.read_txn()?;
    read_job_history_in_txn(vault, &txn, filter, viewer)
}

/// [`read_job_history`] in `txn`.
fn read_job_history_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    filter: &JobHistoryFilter,
    viewer: HistoryViewer,
) -> crate::Result<JobHistory> {
    let jobs = vault.gpu_jobs_in_txn(txn)?;
    let claims = claims_in_txn(vault, txn)?;
    let orders = vault.work_orders_in_txn(txn)?;
    let unattributed = unattributed_in_txn(vault, txn)?;
    let mut observations = Vec::new();
    for key in project::attempt_keys(&jobs, &claims) {
        if let Some(observation) = vault.job_observation_in_txn(txn, &key)? {
            observations.push(observation);
        }
    }
    let mut windows: BTreeSet<(EntityId, u32)> = claims
        .iter()
        .filter(|claim| !claim.is_open())
        .map(|claim: &UnitClaim| (claim.line, claim.period))
        .collect();
    for record in &unattributed {
        windows.extend(record.line_period());
    }
    let mut periods = Vec::with_capacity(windows.len());
    for (line, index) in windows {
        if let Some(period) = stored_period_in_txn(vault, txn, &line, index)? {
            periods.push(period);
        }
    }
    Ok(project(
        &HistoryInputs {
            jobs: &jobs,
            claims: &claims,
            periods: &periods,
            orders: &orders,
            observations: &observations,
            unattributed: &unattributed,
        },
        filter,
        viewer,
    ))
}
