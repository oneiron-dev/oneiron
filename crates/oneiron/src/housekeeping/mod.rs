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

mod claim_vad_payment;
mod report;
mod schedule;
mod sweeps;
mod sync_work;
#[cfg(test)]
mod tests;
mod wake;

pub(crate) use self::claim_vad_payment::ClaimVadPayment;
pub use self::claim_vad_payment::ClaimVadPaymentWorker;
pub use self::report::{
    HardEraseWork, HousekeepingReport, SecretLiftWork, SweepOutcome, SweepReport, SweepWork,
};
pub(crate) use self::wake::note_wake_in_txn;

use crate::Vault;
use crate::error::Result;

use self::schedule::SweepState;

pub(crate) use crate::store::housekeeping_schedule::HousekeepingHandle;
use crate::store::housekeeping_schedule::{DAY, Deadline, HOUR, MINUTE, Runner};
pub use crate::store::housekeeping_schedule::{
    HostOnlyReason, HousekeepingBudget, HousekeepingSweep,
};

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
    /// row of the report. Unless the host has asked it to stop, the pass
    /// first runs one capped communication projector pass, whose failure is
    /// logged and never fails a sweep.
    pub fn housekeeping(&self, budget: HousekeepingBudget) -> Result<HousekeepingReport> {
        if !budget.deadline().stopped() {
            crate::comm::run_comm_projector_housekeeping_step(self);
        }
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
    /// env's owed body collection (FIX 2413), and the earliest deadline of
    /// the retained peer work (FIX 11183). Cache and retention hygiene never
    /// wake a vault. Reads one row per sweep, the schedule and the retained
    /// work queues, so a host can ask every time it stops the vault.
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
        sync_work::push_retained_work_due_at(self, &mut owed)?;
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
