//! The engine's housekeeping pass: every sweep the engine relies on, run when due.
//!
//! The engine owns no timer (ARCH-0026). A host calls [`Vault::housekeeping`] on
//! its own tick, off the request path, and the owner runs
//! [`Vault::housekeeping_all`] through `oneiron maintain`. A host that binds
//! model offers calls the `_with_access` form of each, lending the access its
//! offers hold to the model pack retirement sweep (FIX 20193); `oneiron
//! maintain` lends the access the router `serve` would build holds: the
//! routes its `[models]` config binds and their on-device views, and the
//! models the vault's mesh discovery rows hold (FIX 22059, 22189). Each
//! sweep has a cadence and its own bound. Its schedule lives in
//! the LIVE `HOUSEKEEPING_SCHEDULE` side table and is written when a run ends,
//! so a restart in the middle of a pass resumes the sweeps that had not
//! finished, never runs a finished one early, and never skips one forever. A
//! sweep that fails or panics is reported and retried on a later pass; it
//! never stops the others.
//!
//! The pass only retires what the engine already said would retire: a lease
//! past its expiry, a print past its retention deadline, a confirm past its
//! window, an erasure obligation the owner queued. It never refuses or holds
//! the owner's work. Sweeps that need authority only a host holds are listed
//! in every report with the reason they did not run.
//!
//! Every pass but a support holder's one-sweep repair, unless the host
//! asked it to stop, first releases the due watcher ticks and prunes the
//! hook feeds once, by the fact-hook runner's rule (FIX 22180): a host that
//! runs no runner still settles a watch TASK at its due time and keeps the
//! feeds bounded, and `oneiron maintain` settles a stopped vault's due watch
//! TASKs. Such a pass also drops the task-held inquiry answers whose task
//! has ended or whose `valid_until` has come (Engine ruling
//! INQUIRE-HOLDER-EVICT), so they leave memory within one host tick.
//!
//! A host that stops a vault between uses asks [`Vault::housekeeping_wake_at`]
//! when it must run the vault again for a retirement that comes due, a model
//! pack's notice mark or retirement-day move included (FIX 22059).

mod claim_vad_payment;
mod report;
mod schedule;
mod sweeps;
mod sync_work;
pub(crate) mod tables;
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
use crate::llm::model_pack::AccessSnapshot;

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
    /// first runs one capped communication projector pass, then releases
    /// the due watcher ticks and prunes the hook feeds once (FIX 22180),
    /// whose failures are logged and never fail a sweep, drops the
    /// task-held inquiry answers whose task has ended, and advances the
    /// pending check-ins due by now (ROLES-CHECKIN P2.3). The model pack
    /// retirement sweep runs against no model access: a host that binds
    /// model offers calls [`Self::housekeeping_with_access`].
    pub fn housekeeping(&self, budget: HousekeepingBudget) -> Result<HousekeepingReport> {
        self.housekeeping_with_access(budget, &AccessSnapshot::new())
    }

    /// [`Self::housekeeping`] on a host whose offers hold `access` (FIX
    /// 5366): the model pack retirement sweep resolves the active pack's
    /// roles against it, for the notices of the retiring models they use
    /// (FIX 20193).
    pub fn housekeeping_with_access(
        &self,
        budget: HousekeepingBudget,
        access: &AccessSnapshot,
    ) -> Result<HousekeepingReport> {
        let deadline = budget.deadline();
        if !deadline.stopped() {
            self.store
                .record_hooks
                .run_comm_projector_housekeeping_step(self);
        }
        release_ticks_and_prune_hook_feeds(self, &deadline);
        evict_ended_inquiry_answers(self, &deadline);
        advance_due_check_ins(self, &deadline);
        #[cfg(feature = "sync")]
        admit_carried_turn_program_wakes(self, &deadline);
        self.housekeeping_pass(Selection::Due, budget, access)
    }

    /// Runs every engine sweep now, due or not, and reschedules each from
    /// now: the owner's "run housekeeping now". Unless the host has asked it
    /// to stop, it first releases the due watcher ticks and prunes the hook
    /// feeds once, drops the ended tasks' inquiry answers and advances the
    /// due pending check-ins, as [`Self::housekeeping`] does, so `oneiron maintain` settles a stopped
    /// vault's due watch TASKs (FIX 22180). The model pack
    /// retirement sweep runs against no model access: a host that holds model
    /// offers, `serve` or `oneiron maintain` with the offers its config and
    /// the vault's mesh discovery rows bind, calls
    /// [`Self::housekeeping_all_with_access`] (FIX 22059, 22189).
    pub fn housekeeping_all(&self, budget: HousekeepingBudget) -> Result<HousekeepingReport> {
        self.housekeeping_all_with_access(budget, &AccessSnapshot::new())
    }

    /// [`Self::housekeeping_all`] on a host whose offers hold `access`, as
    /// [`Self::housekeeping_with_access`] lends it.
    pub fn housekeeping_all_with_access(
        &self,
        budget: HousekeepingBudget,
        access: &AccessSnapshot,
    ) -> Result<HousekeepingReport> {
        let deadline = budget.deadline();
        release_ticks_and_prune_hook_feeds(self, &deadline);
        evict_ended_inquiry_answers(self, &deadline);
        advance_due_check_ins(self, &deadline);
        #[cfg(feature = "sync")]
        admit_carried_turn_program_wakes(self, &deadline);
        self.housekeeping_pass(Selection::All, budget, access)
    }

    /// Runs the engine sweep `sweep` alone now and reschedules it from now: a
    /// support holder's repair (FIX 4407), never [`Self::housekeeping_all`].
    pub(crate) fn housekeeping_one(
        &self,
        sweep: HousekeepingSweep,
        budget: HousekeepingBudget,
    ) -> Result<HousekeepingReport> {
        self.housekeeping_pass(Selection::One(sweep), budget, &AccessSnapshot::new())
    }

    /// When a vault that is not running must next run a pass, or `None` when
    /// it owes no retirement: the earliest deadline a door noted for a secret
    /// lease, a voice print, a critical confirm or a shared act's window, not
    /// before that sweep is next due (a failing sweep waits out its backoff),
    /// and the erasure sweep's due time while an obligation waits, and a left
    /// env's owed body collection (FIX 2413), and the earliest deadline of
    /// the retained peer work (FIX 11183), and a paced verb call's window or
    /// deadline (FIX 8753), and the first day to come on which the model
    /// pack retirement pass owes work, a notice mark with no notice recorded
    /// or a retirement-day move (FIX 22059), and the next due watcher tick on
    /// the node that releases them (FIX 22180), and the first due pending
    /// check-in (ROLES-CHECKIN P2.3). Cache and retention hygiene
    /// never wake a vault. Reads one row per sweep, the schedule, the
    /// retained work queues, the installed model packs' kept checks (FIX
    /// 20043) and notice records, and the first due index row, so a host can
    /// ask every time it stops the vault.
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
        // A paced verb call's window opening or deadline (FIX 8753): the
        // host's settler runs its turn once the vault is up again.
        if let Some(at) = self.paced_verb_wake_at()? {
            owed.push((HousekeepingSweep::GateDecisionRetention, at));
        }
        // A model pack's notice mark or retirement day (FIX 22059): the pass
        // records the move and sends the notices on the day itself.
        if let Some(at) = self.model_pack_retirement_wake_at()? {
            owed.push((HousekeepingSweep::ModelPackRetirement, at));
        }
        // The next due watcher tick (FIX 22180): the host's hook runner, or
        // its first housekeeping pass, releases it once the vault is up
        // again. The minute carrier, the host tick's own cadence, keeps the
        // wake within a minute of the tick's due time.
        if let Some(at) = crate::runtime_hooks::next_tick_release_at(self)? {
            owed.push((HousekeepingSweep::ModelPackRetirement, at));
        }
        // The next due timer turn program (untangle slice 6.8c), released
        // where the ticks are, on the same carrier.
        if let Some(at) = crate::dreamer_runner::next_program_timer_at(self)? {
            owed.push((HousekeepingSweep::ModelPackRetirement, at));
        }
        // The first due pending check-in (ROLES-CHECKIN P2.3, 2e): the
        // pass above advances it, on the same carrier.
        if let Some(at) = crate::check_in::next_check_in_due_at(self)? {
            owed.push((HousekeepingSweep::ModelPackRetirement, at));
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
        access: &AccessSnapshot,
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
                Some(self.run_scheduled_sweep(sweep, state, every, &deadline, owner_asked, access));
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
    /// earlier pass left for later, failed or was cut short on. `access` is
    /// what the host's offers hold, lent to the model pack retirement sweep.
    fn run_scheduled_sweep(
        &self,
        sweep: HousekeepingSweep,
        state: SweepState,
        every: u64,
        deadline: &Deadline,
        owner_asked: bool,
        access: &AccessSnapshot,
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
                access,
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

/// The hook feed step of a housekeeping pass, the host tick's and the
/// owner's alike (FIX 22180), unless the host asked the pass to stop. It
/// releases the due watcher TASKs into the tick feed on the vault's home, as
/// each fact-hook runner pass does, one bounded release after another until
/// none remain or `deadline` passes, then prunes the hook feeds once by the
/// runner's rule, at most `HOOK_PASS_ENTRIES` rows a feed: a host that runs
/// no hook runner (`--no-hooks`, no sandbox, a sandbox that failed to load)
/// still settles a watch TASK at its due time and drops the ticks no binding
/// reads again, and `oneiron maintain` settles a stopped vault's due watch
/// TASKs. Due timer and moved feed turn programs are released after the ticks
/// (untangle slice 6.8c). Beside a live runner, a row two releases both plan moves once, and
/// a row two prunes both plan goes once (`prune_hook_feeds`). A failed
/// release or prune is logged and retried on the next pass.
/// The turn-program wakes another machine carried to this one (FIX 5266).
/// On the elected home they arrive with no turn here to drain them, so each
/// pass merges the carried rows (a wake that came before its arming is taken
/// once the arming has) and admits every wake owed here. Off the home the
/// merge does nothing and the admission passes riding wakes by. A failure is
/// logged by the admission and waits for the next pass.
#[cfg(feature = "sync")]
fn admit_carried_turn_program_wakes(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    vault.merge_carried_turn_program_wakes();
    vault.admit_owed_turn_programs(vault.now_recorded_at());
}

fn release_ticks_and_prune_hook_feeds(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    loop {
        match crate::runtime_hooks::release_due_ticks(vault, vault.now_recorded_at()) {
            Ok(true) if !deadline.passed() => {}
            Ok(_) => break,
            Err(error) => {
                tracing::warn!(%error, "housekeeping: due watcher ticks wait for the next pass");
                break;
            }
        }
    }
    if deadline.stopped() {
        return;
    }
    // Timer and feed turn programs are released beside the ticks (untangle
    // slice 6.8c), and what they owe is admitted.
    crate::dreamer_runner::release_program_wakes(vault, vault.now_recorded_at());
    if deadline.stopped() {
        return;
    }
    if let Err(error) =
        crate::runtime_hooks::prune_hook_feeds(vault, crate::runtime_hooks::HOOK_PASS_ENTRIES)
    {
        tracing::warn!(%error, "housekeeping: passed hook feed rows wait for the next pass");
    }
}

/// Drops the task-held inquiry answers whose task has ended or whose
/// `valid_until` has come (Engine ruling INQUIRE-HOLDER-EVICT), unless the
/// host asked the pass to stop. A failure is logged; the next pass, or the
/// next send or read of an answer, drops them.
fn evict_ended_inquiry_answers(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    if let Err(error) = vault.evict_inquiry_answers() {
        tracing::warn!(%error, "housekeeping: ended inquiry answers wait for the next pass");
    }
}

/// Advances the pending check-ins due by now (ROLES-CHECKIN P2.3, 2e): a
/// rung whose wait is over climbs, the asker's `until` lets the ask go, and
/// the chain's end applies canon's table "When nobody answers". A row that
/// fails stays due for the next pass.
fn advance_due_check_ins(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    if let Err(error) = vault.advance_due_check_ins() {
        tracing::warn!(%error, "housekeeping: due check-ins wait for the next pass");
    }
}
