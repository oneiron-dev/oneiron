//! The engine's housekeeping pass: every sweep the engine relies on, run when due.
//!
//! The engine owns no timer (ARCH-0026). A host calls [`Vault::housekeeping`] on
//! its own tick, off the request path, and the owner runs
//! [`Vault::housekeeping_all`] through `oneiron maintain`. Each sweep has a
//! cadence and its own bound. Its schedule lives in the LIVE
//! `HOUSEKEEPING_SCHEDULE` side table and is written when a run ends, so a
//! restart in the middle of a pass resumes the sweeps that had not finished,
//! never runs a finished one early, and never skips one forever. A sweep that
//! fails or panics is reported and retried on a later pass; it never stops the
//! others.
//!
//! The pass only retires what the engine already said would retire: a lease
//! past its expiry, a print past its retention deadline, a confirm past its
//! window, an erasure obligation the owner queued. It never refuses or holds
//! the owner's work. Sweeps that need authority only a host holds are listed
//! in every report with the reason they did not run.
//!
//! A host that stops a vault between uses asks [`Vault::housekeeping_wake_at`]
//! when it must run the vault again for a retirement that comes due.

mod report;
mod schedule;
mod sweeps;
mod sync_work;
#[cfg(test)]
mod tests;
mod wake;

pub use self::report::{
    HardEraseWork, HousekeepingReport, SecretLiftWork, SweepOutcome, SweepReport, SweepWork,
};
pub(crate) use self::wake::note_wake_in_txn;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::Vault;
use crate::error::Result;

use self::schedule::SweepState;

/// One sweep the housekeeping pass knows. The engine runs the first fourteen;
/// the rest need a host's authority and are reported, never run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HousekeepingSweep {
    /// Expires every active secret lease past its deadline and removes its
    /// registered file.
    SecretLeaseExpiry,
    /// Demotes critical-write confirms still Auto past their 300-second window.
    CriticalConfirmExpiry,
    /// Clears symbol-lease holds past their expiry.
    SymbolLeaseExpiry,
    /// Deletes voice prints past their retention deadline.
    VoicePrintRetention,
    /// Expires signing documents and recipients past their signing window.
    EsignExpiry,
    /// Re-queues the seal of a signing request whose trigger was missed.
    EsignSealBackstop,
    /// Lapses overdue open commitments and repairs missed close hooks.
    CommitmentLapse,
    /// Finishes staged key retirements and ages out gate decisions past the
    /// owner's horizon.
    GateDecisionRetention,
    /// Discharges queued erasure obligations from historical carriers.
    HardEraseSweep,
    /// Evicts cached graph walks past the longest serve window.
    PprCacheEviction,
    /// Tells the live Owners of each waiting shared act whose window has
    /// passed with no live objection (OF-163). Effect-free.
    SharedActMaturity,
    /// Works the queued historical lift run (OF-067): rows stored before the
    /// write wall saw them are masked through their own doors, and each hit
    /// no door places files a lift proposal. Idle when no run is queued, and
    /// paused while the owner's switch is off.
    SecretLiftHistory,
    /// Finishes owed claim VAD consolidations (FIX 9598): an approval whose
    /// writer stopped, or whose consolidation failed, before it was done.
    ClaimVadDebt,
    /// Raises the found-key notices left due past one write's share (OF-560,
    /// FIX 2648), for a vault no later write comes to.
    FoundKeyNotices,
    /// Due signing reminders.
    EsignReminders,
    /// Consult deadlines and their expiry digests.
    ConsultSettlement,
    /// Pruning of resolved or stale moderation holds.
    PolicyHoldPrune,
    /// The TASK receipt attribution pump.
    TaskAttribution,
    /// Reclaim of attempt leases a live worker no longer holds.
    AttemptLeaseReclaim,
    /// Scheduled self-heal detector runs.
    SelfHealDetectorRuns,
}

/// Why a sweep is the host's to run, not the engine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOnlyReason {
    /// Each dispatch needs an authenticated actor, grants and a window from
    /// the host; a timer is not that authority.
    NeedsAuthenticatedDispatch,
    /// The host supplies per-asker native routes and drives consult settlement
    /// on each admitted housekeeping pass; expiry itself needs no actor.
    NeedsHostDigestRoute,
    /// Only an authenticated owner may prune their holds.
    NeedsAuthenticatedOwner,
    /// Execution facts come from the host's receipt source.
    NeedsHostReceiptFacts,
    /// Attempt leases carry no heartbeat, so only the host knows which leases
    /// its live workers hold; the host reclaims dead ones when it starts.
    NeedsLiveLeaseSet,
    /// A detector run needs the host's instance, scope and observations.
    NeedsHostDetectorInputs,
}

/// How a sweep runs.
#[derive(Debug, Clone, Copy)]
enum Runner {
    Engine {
        /// Seconds between runs.
        every: u64,
        /// Also due on the first pass of every handle, whatever the schedule
        /// says: work an interrupted owner act left durable must not wait a
        /// whole cadence after a restart.
        at_open: bool,
    },
    Host(HostOnlyReason),
}

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

impl HousekeepingSweep {
    /// Every sweep, in report order.
    pub const ALL: [Self; 20] = [
        Self::SecretLeaseExpiry,
        Self::CriticalConfirmExpiry,
        Self::SymbolLeaseExpiry,
        Self::VoicePrintRetention,
        Self::EsignExpiry,
        Self::EsignSealBackstop,
        Self::CommitmentLapse,
        Self::GateDecisionRetention,
        Self::HardEraseSweep,
        Self::PprCacheEviction,
        Self::SharedActMaturity,
        Self::SecretLiftHistory,
        Self::ClaimVadDebt,
        Self::FoundKeyNotices,
        Self::EsignReminders,
        Self::ConsultSettlement,
        Self::PolicyHoldPrune,
        Self::TaskAttribution,
        Self::AttemptLeaseReclaim,
        Self::SelfHealDetectorRuns,
    ];

    /// The sweep's stable code: its schedule key and its log field.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SecretLeaseExpiry => "secret_lease_expiry",
            Self::CriticalConfirmExpiry => "critical_confirm_expiry",
            Self::SymbolLeaseExpiry => "symbol_lease_expiry",
            Self::VoicePrintRetention => "voice_print_retention",
            Self::EsignExpiry => "esign_expiry",
            Self::EsignSealBackstop => "esign_seal_backstop",
            Self::CommitmentLapse => "commitment_lapse",
            Self::GateDecisionRetention => "gate_decision_retention",
            Self::HardEraseSweep => "hard_erase_sweep",
            Self::PprCacheEviction => "ppr_cache_eviction",
            Self::SharedActMaturity => "shared_act_maturity",
            Self::SecretLiftHistory => "secret_lift_history",
            Self::ClaimVadDebt => "claim_vad_debt",
            Self::FoundKeyNotices => "found_key_notices",
            Self::EsignReminders => "esign_reminders",
            Self::ConsultSettlement => "consult_settlement",
            Self::PolicyHoldPrune => "policy_hold_prune",
            Self::TaskAttribution => "task_attribution",
            Self::AttemptLeaseReclaim => "attempt_lease_reclaim",
            Self::SelfHealDetectorRuns => "self_heal_detector_runs",
        }
    }

    /// Cadences: the code's own stated duty where canon is silent. A secret
    /// lease's expiry, a print's retention deadline and a confirm's 300-second
    /// window make their sweep due at that moment (the doors note them), so
    /// those sweeps run then and hourly besides, for a deadline no door noted.
    /// The seal backstop runs every fifteen minutes (ARCH-0064 SGN-04); the
    /// erasure sweep daily, hourly while an obligation waits (ARCH-0038's
    /// deadline is 30 days); the graph-walk cache daily. A shared act's
    /// deadline makes the maturity sweep due then (its start notes it), and
    /// it runs hourly besides, for an act an objection withdrawal released.
    /// The lift sweep looks for a queued run every fifteen minutes, and a run
    /// left unfinished at a pass's deadline is due again at once. Owed claim
    /// VAD work runs at open, for an approval a stopped process left, and
    /// every fifteen minutes. The found-key drain looks for due notices every
    /// fifteen minutes.
    const fn runner(self) -> Runner {
        const fn engine(every: u64) -> Runner {
            Runner::Engine {
                every,
                at_open: false,
            }
        }
        match self {
            Self::SecretLeaseExpiry | Self::CriticalConfirmExpiry | Self::VoicePrintRetention => {
                engine(HOUR)
            }
            Self::SymbolLeaseExpiry => engine(5 * MINUTE),
            Self::EsignExpiry
            | Self::EsignSealBackstop
            | Self::CommitmentLapse
            | Self::SecretLiftHistory
            | Self::FoundKeyNotices => engine(15 * MINUTE),
            Self::GateDecisionRetention => Runner::Engine {
                every: HOUR,
                at_open: true,
            },
            Self::HardEraseSweep | Self::PprCacheEviction => engine(DAY),
            Self::SharedActMaturity => engine(HOUR),
            Self::ClaimVadDebt => Runner::Engine {
                every: 15 * MINUTE,
                at_open: true,
            },
            Self::EsignReminders => Runner::Host(HostOnlyReason::NeedsAuthenticatedDispatch),
            Self::ConsultSettlement => Runner::Host(HostOnlyReason::NeedsHostDigestRoute),
            Self::PolicyHoldPrune => Runner::Host(HostOnlyReason::NeedsAuthenticatedOwner),
            Self::TaskAttribution => Runner::Host(HostOnlyReason::NeedsHostReceiptFacts),
            Self::AttemptLeaseReclaim => Runner::Host(HostOnlyReason::NeedsLiveLeaseSet),
            Self::SelfHealDetectorRuns => Runner::Host(HostOnlyReason::NeedsHostDetectorInputs),
        }
    }
}

/// How long one pass may keep starting work. A sweep in flight finishes; the
/// budget is checked before each sweep and between the pages of a paged one.
/// A pass always runs at least one due sweep, so it makes progress, unless
/// its host has asked it to stop.
#[derive(Debug, Clone, Default)]
pub struct HousekeepingBudget {
    time: Option<Duration>,
    stop: Option<Arc<AtomicBool>>,
}

impl HousekeepingBudget {
    /// Start no new sweep or page once `time` has passed.
    pub fn within(time: Duration) -> Self {
        Self {
            time: Some(time),
            stop: None,
        }
    }

    /// No time bound: every sweep runs to its own bound.
    pub fn unbounded() -> Self {
        Self::default()
    }

    /// Also start no new sweep or page once `stop` is set: a host that is
    /// shutting down sets it, then waits for the pass to return.
    #[must_use]
    pub fn stop_when(self, stop: Arc<AtomicBool>) -> Self {
        Self {
            stop: Some(stop),
            ..self
        }
    }

    fn deadline(&self) -> Deadline {
        Deadline {
            at: self.time.and_then(|time| Instant::now().checked_add(time)),
            stop: self.stop.clone(),
        }
    }
}

/// When a pass stops starting work.
#[derive(Debug, Clone)]
struct Deadline {
    at: Option<Instant>,
    stop: Option<Arc<AtomicBool>>,
}

impl Deadline {
    /// The host asked the pass to stop.
    fn stopped(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Acquire))
    }

    fn passed(&self) -> bool {
        self.stopped() || self.at.is_some_and(|at| Instant::now() >= at)
    }
}

/// Per-handle housekeeping state: one pass at a time, and whether this handle
/// has run its first pass yet.
#[derive(Debug, Default)]
pub(crate) struct HousekeepingHandle {
    first_pass_done: bool,
}

/// Which sweeps a pass considers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    Due,
    All,
    /// One engine sweep now, asked by a support holder (FIX 4407).
    One(HousekeepingSweep),
}

/// A sweep a pass will start if its budget allows.
struct Due {
    /// When it fell due; 0 when it was asked for.
    at: u64,
    /// Its place in [`HousekeepingSweep::ALL`].
    index: usize,
    every: u64,
    /// Due because it was asked for, not because its schedule says so.
    forced: bool,
}

impl Vault {
    /// Runs every engine sweep that is due, oldest-due first, within
    /// `budget`. A host calls this on its own tick, off the request path. An
    /// error means the schedule could not be read; a sweep's own failure is a
    /// row of the report.
    pub fn housekeeping(&self, budget: HousekeepingBudget) -> Result<HousekeepingReport> {
        self.housekeeping_pass(Selection::Due, budget)
    }

    /// Runs every engine sweep now, due or not, and reschedules each from
    /// now: the owner's "run housekeeping now".
    pub fn housekeeping_all(&self, budget: HousekeepingBudget) -> Result<HousekeepingReport> {
        self.housekeeping_pass(Selection::All, budget)
    }

    /// Runs the engine sweep `sweep` alone now and reschedules it from now: a
    /// support holder's repair (FIX 4407), never [`Self::housekeeping_all`].
    pub(crate) fn housekeeping_one(
        &self,
        sweep: HousekeepingSweep,
        budget: HousekeepingBudget,
    ) -> Result<HousekeepingReport> {
        self.housekeeping_pass(Selection::One(sweep), budget)
    }

    /// When a vault that is not running must next run a pass, or `None` when
    /// it owes no retirement: the earliest deadline a door noted for a secret
    /// lease, a voice print, a critical confirm or a shared act's window, not
    /// before that sweep is next due (a failing sweep waits out its backoff),
    /// and the erasure sweep's due time while an obligation waits, and a left
    /// env's owed body collection (FIX 2413). Cache and retention hygiene
    /// never wake a vault. Reads one row per sweep and the schedule, never a
    /// whole table, so a host can ask every time it stops the vault.
    pub fn housekeeping_wake_at(&self) -> Result<Option<u64>> {
        let states = schedule::read_states(self)?;
        let noted = {
            let txn = self.store.env.read_txn()?;
            let mut noted = Vec::new();
            for sweep in wake::WAKE_SWEEPS {
                if let Some(at) = wake::earliest_in_txn(&self.store, &txn, sweep)? {
                    noted.push((sweep, at));
                }
            }
            noted
        };
        let mut owed = noted;
        if schedule::erase_obligation_waiting(self)? {
            owed.push((HousekeepingSweep::HardEraseSweep, 0));
        }
        if let Some(at) = sync_work::left_env_body_collect_due_at(self)? {
            owed.push((HousekeepingSweep::GateDecisionRetention, at));
        }
        let mut earliest: Option<u64> = None;
        for (sweep, at) in owed {
            let Runner::Engine { every, .. } = sweep.runner() else {
                continue;
            };
            let due = schedule::due_at(self, sweep, states.get(&sweep), every)?;
            let wake = at.max(due);
            earliest = Some(earliest.map_or(wake, |seen| seen.min(wake)));
        }
        Ok(earliest)
    }

    fn housekeeping_pass(
        &self,
        selection: Selection,
        budget: HousekeepingBudget,
    ) -> Result<HousekeepingReport> {
        let mut handle = self
            .housekeeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deadline = budget.deadline();
        let started_at = self.now_recorded_at();
        let mut states = schedule::read_states(self)?;

        let mut rows: Vec<Option<SweepOutcome>> = vec![None; HousekeepingSweep::ALL.len()];
        let mut due: Vec<Due> = Vec::new();
        for (index, sweep) in HousekeepingSweep::ALL.into_iter().enumerate() {
            if let Selection::One(asked) = selection
                && asked != sweep
            {
                continue;
            }
            match sweep.runner() {
                Runner::Host(reason) => rows[index] = Some(SweepOutcome::HostOnly { reason }),
                Runner::Engine { every, at_open } => {
                    if selection != Selection::Due || (at_open && !handle.first_pass_done) {
                        due.push(Due {
                            at: 0,
                            index,
                            every,
                            forced: true,
                        });
                        continue;
                    }
                    match schedule::due_at(self, sweep, states.get(&sweep), every)? {
                        at if at <= started_at => due.push(Due {
                            at,
                            index,
                            every,
                            forced: false,
                        }),
                        at => rows[index] = Some(SweepOutcome::NotDue { due_at: at }),
                    }
                }
            }
        }
        // Oldest-due first: a sweep the budget left behind runs ahead of
        // sweeps that fell due after it, so none is starved.
        due.sort_unstable_by_key(|due| (due.at, due.index));

        let mut ran_any = false;
        for Due {
            index,
            every,
            forced,
            ..
        } in due
        {
            let sweep = HousekeepingSweep::ALL[index];
            let state = states.remove(&sweep).unwrap_or_default();
            if deadline.stopped() || (ran_any && deadline.passed()) {
                rows[index] = Some(self.leave_for_later(sweep, state, forced, started_at));
                continue;
            }
            ran_any = true;
            let owner_asked = selection == Selection::All;
            rows[index] =
                Some(self.run_scheduled_sweep(sweep, state, every, &deadline, owner_asked));
        }
        if !matches!(selection, Selection::One(_)) {
            handle.first_pass_done = true;
        }

        let sweeps = HousekeepingSweep::ALL
            .into_iter()
            .zip(rows)
            .filter(|(sweep, _)| !matches!(selection, Selection::One(asked) if asked != *sweep))
            .map(|(sweep, outcome)| SweepReport {
                sweep,
                outcome: outcome.unwrap_or(SweepOutcome::OutOfBudget),
            })
            .collect();
        Ok(HousekeepingReport { started_at, sweeps })
    }

    /// The row of a due sweep the pass did not start. One the schedule made
    /// due stays due; one that was due only because it was asked for (the
    /// owner's "now", or the first pass of a handle) keeps the request, so a
    /// later pass runs it rather than waiting out its cadence.
    fn leave_for_later(
        &self,
        sweep: HousekeepingSweep,
        state: SweepState,
        forced: bool,
        at: u64,
    ) -> SweepOutcome {
        if forced && let Err(error) = schedule::write_state(self, sweep, &state.requested(at)) {
            return SweepOutcome::Failed { kind: error.kind() };
        }
        SweepOutcome::OutOfBudget
    }

    /// Runs one sweep between its start marker and its finish row. The marker
    /// is what tells the next pass that a run was interrupted. The run is the
    /// owner's when this pass is, or when it answers an owner's request an
    /// earlier pass left for later, failed or was cut short on.
    fn run_scheduled_sweep(
        &self,
        sweep: HousekeepingSweep,
        state: SweepState,
        every: u64,
        deadline: &Deadline,
        owner_asked: bool,
    ) -> SweepOutcome {
        let start = self.now_recorded_at();
        let running = state.started(start, owner_asked);
        if let Err(error) = schedule::write_state(self, sweep, &running) {
            return SweepOutcome::Failed { kind: error.kind() };
        }
        // The wake rows this run covers: noted before it started and due by
        // then. A row noted while it runs stays for the next run.
        let covered = wake::due_by(self, sweep, start).unwrap_or_default();
        #[cfg(test)]
        let injected = tests::injected(sweep);
        #[cfg(test)]
        if injected == Some(tests::Injected::Crash) {
            panic!("test: the process died in the middle of a sweep");
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            match injected {
                Some(tests::Injected::Fail) => {
                    return Err(crate::Error::InvariantViolation(
                        "test: an injected sweep failure",
                    ));
                }
                Some(tests::Injected::Panic) => panic!("test: an injected sweep panic"),
                _ => {}
            }
            sweeps::run(
                self,
                sweep,
                start,
                deadline,
                running.cursor.as_deref(),
                running.owners(),
            )
        }));
        let end = self.now_recorded_at();
        let (outcome, finished) = match result {
            Ok(Ok(run)) => {
                // An owner's erasure run that left a window uncompacted (a
                // caller held it, a write raced it, its cut was not proved,
                // or a legal hold kept it) has not answered the owner: it is
                // retried as the owner's, after the backoff.
                let owner_left = running.owners()
                    && matches!(run.work, SweepWork::HardErase(work)
                        if work.windows_deferred_live > 0
                            || work.windows_deferred_raced > 0
                            || work.windows_deferred_unproved > 0
                            || work.windows_deferred_held > 0);
                let items_failed = run.work.items_failed() > 0 || owner_left;
                if run.complete && !items_failed {
                    // A walk that began before this run covers the rows due
                    // by when it began. A row the clear leaves behind costs
                    // one run that finds nothing.
                    let mut covered = covered;
                    if let Some(until) = run.covered_until {
                        covered.retain(|&(_, at, _)| at <= until);
                    }
                    let _ = wake::clear(self, &covered);
                }
                let finished = running.ran(end, every, run.cursor, run.complete, items_failed);
                (
                    SweepOutcome::Ran {
                        work: run.work,
                        complete: run.complete,
                    },
                    finished,
                )
            }
            Ok(Err(error)) => (
                SweepOutcome::Failed { kind: error.kind() },
                running.failed(end, every),
            ),
            Err(_) => (SweepOutcome::Panicked, running.failed(end, every)),
        };
        match schedule::write_state(self, sweep, &finished) {
            Ok(()) => outcome,
            // The run's own work committed, but its schedule did not: the
            // start marker stays, so the next pass treats the run as
            // interrupted and retries it after the backoff.
            Err(error) => SweepOutcome::Failed { kind: error.kind() },
        }
    }
}
