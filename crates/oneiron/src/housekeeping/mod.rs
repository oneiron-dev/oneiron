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
//! engine sweep is a job of the one runner (DESIGN 15-setting-primitive,
//! stage 5a; [`crate::schedule`]): its cadence is a Setting key
//! (`housekeeping.<sweep>.every`), it keeps its own bound, and its schedule
//! row is written when a run starts and when it ends, so a restart in the
//! middle of a pass resumes the sweeps that had not finished, never runs a
//! finished one early, and never skips one forever. A sweep that fails or
//! panics is reported and retried after its backoff; it never stops the
//! others. A handle's first pass arms every cadence job from its key and
//! runs the sweeps that run at each start.
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
pub(crate) mod jobs;
mod lapse_writer;
mod report;
pub(crate) mod setting_keys;
mod sweeps;
mod sync_work;
#[cfg(test)]
mod tests;
mod wake;

pub(crate) use self::claim_vad_payment::ClaimVadPayment;
pub use self::claim_vad_payment::ClaimVadPaymentWorker;
pub(crate) use self::lapse_writer::{
    commitment_lapse_writer_id, ensure_commitment_lapse_writer_machine,
};
pub use self::report::{
    HardEraseWork, HousekeepingReport, SecretLiftWork, SweepOutcome, SweepReport, SweepWork,
};
pub(crate) use self::wake::note_wake_in_txn;

use crate::Vault;
use crate::error::{ErrorKind, Result};
use crate::llm::model_pack::AccessSnapshot;
use crate::schedule::{JobOutcome, JobPass, JobRun, JobSpec, When};

pub(crate) use crate::store::housekeeping_schedule::HousekeepingHandle;
use crate::store::housekeeping_schedule::{Deadline, Runner};
pub use crate::store::housekeeping_schedule::{
    HostOnlyReason, HousekeepingBudget, HousekeepingSweep,
};

/// Which runs a pass asks for beside the ones that are due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// None: the host's tick.
    Due,
    /// Every engine sweep: the owner's "run housekeeping now".
    All,
}

/// Whether `spec` is a job whose cadence is a Setting key.
fn is_cadence_job(spec: &JobSpec) -> bool {
    matches!(spec.when, When::Setting(_))
}

/// Whether `spec` is one of the engine sweeps' jobs.
fn is_sweep_job(spec: &JobSpec) -> bool {
    jobs::sweep_of(spec.code).is_some()
}

impl Vault {
    /// Runs every engine sweep that is due, oldest-due first, within
    /// `budget`, beside every other armed job that is due. A host calls this
    /// on its own tick, off the request path. An error means the schedule
    /// could not be read; a sweep's own failure is a row of the report.
    /// Unless the host has asked it to stop, the pass first runs one capped
    /// communication projector pass, then prunes the hook feeds once (FIX
    /// 22180), whose failures are logged and never fail a sweep, and drops the
    /// task-held inquiry answers whose task has ended. The pending check-ins
    /// due by now advance, and the due watcher ticks and timer turn programs
    /// release on the node that releases ticks, as armed jobs of the runner
    /// (ROLES-CHECKIN P2.3; stage 5b); after the runner, unless asked to stop,
    /// it releases the feed turn programs and admits every owed wake once. The
    /// model pack retirement sweep runs against no model access: a host that
    /// binds model offers calls [`Self::housekeeping_with_access`].
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
        prune_hook_feeds_once(self, &deadline);
        evict_ended_inquiry_answers(self, &deadline);
        #[cfg(feature = "sync")]
        admit_carried_turn_program_wakes(self, &deadline);
        let report = self.housekeeping_pass(Asked::Due, &deadline, access);
        release_turn_program_wakes(self, &deadline);
        report
    }

    /// Runs every engine sweep now, due or not, and reschedules each from
    /// now: the owner's "run housekeeping now". Unless the host has asked it
    /// to stop, it first prunes the hook feeds once and drops the ended tasks'
    /// inquiry answers, and after its runner releases the feed turn programs
    /// and admits the owed wakes, as [`Self::housekeeping`] does; its runner
    /// advances the due pending check-ins and runs the due watcher ticks, so
    /// `oneiron maintain` settles a stopped vault's due watch TASKs (FIX
    /// 22180), and the due timer turn programs. The model pack
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
        prune_hook_feeds_once(self, &deadline);
        evict_ended_inquiry_answers(self, &deadline);
        #[cfg(feature = "sync")]
        admit_carried_turn_program_wakes(self, &deadline);
        let report = self.housekeeping_pass(Asked::All, &deadline, access);
        release_turn_program_wakes(self, &deadline);
        report
    }

    /// Runs the engine sweep `sweep` alone now and reschedules it from now: a
    /// support holder's repair (FIX 4407), never [`Self::housekeeping_all`].
    pub(crate) fn housekeeping_one(
        &self,
        sweep: HousekeepingSweep,
        budget: HousekeepingBudget,
    ) -> Result<HousekeepingReport> {
        let deadline = budget.deadline();
        let started_at = self.now_recorded_at();
        let mut runs = Vec::new();
        if let Runner::Engine = sweep.runner() {
            let job = jobs::job_code(sweep);
            let access = AccessSnapshot::new();
            let pass = JobPass {
                deadline: &deadline,
                access: &access,
            };
            let mut run = self.run_job_now(&job, None, &pass)?;
            if run.is_none() {
                // Not armed yet: this handle has not run its first pass.
                crate::schedule::arm_setting_jobs(self, is_sweep_job)?;
                run = self.run_job_now(&job, None, &pass)?;
            }
            runs.extend(run);
        }
        self.sweep_report(started_at, &runs, Some(sweep))
    }

    /// When a vault that is not running must next run a pass, or `None` when
    /// it owes no retirement: the erasure sweep's due time while an obligation
    /// waits, and a left env's owed body collection (FIX 2413), and the
    /// earliest deadline of the retained peer work (FIX 11183), and a paced
    /// verb call's window or deadline (FIX 8753), and the first day to come
    /// on which the model pack retirement pass owes work, a notice mark with
    /// no notice recorded or a retirement-day move (FIX 22059), and the
    /// first due armed job that wakes its host and runs on this node. Among those jobs is each
    /// open pending check-in, due at its next transition (ROLES-CHECKIN P2.3), each waiting
    /// watcher tick and each actor's next timer turn program, due then on the node that releases
    /// ticks (FIX 22180; stage 5b-3), and each deadline a door noted for a secret
    /// lease, a voice print, a critical confirm or a shared act's window (DESIGN
    /// 15-setting-primitive, stage 5b): due at the deadline, and after a pass
    /// that found the sweep backing off or its walk begun before the deadline,
    /// when the sweep is next due. A sweep's cadence never wakes a vault: cache
    /// and retention hygiene wait for the next start. Reads the schedule, the
    /// retained work queues, the installed model packs' kept checks (FIX
    /// 20043) and notice records, and the first due index row, so a host can
    /// ask every time it stops the vault.
    pub fn housekeeping_wake_at(&self) -> Result<Option<u64>> {
        let mut owed = Vec::new();
        if jobs::erase_obligation_waiting(self)? {
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
        let mut earliest: Option<u64> = None;
        {
            let txn = self.store.env.read_txn()?;
            for (sweep, at) in owed {
                let Runner::Engine = sweep.runner() else {
                    continue;
                };
                // A sweep not armed yet is due at its first pass.
                let due = crate::schedule::due_at_in_txn(
                    &self.store,
                    &txn,
                    &jobs::job_code(sweep),
                    None,
                )?
                .unwrap_or(0);
                let wake = at.max(due);
                earliest = Some(earliest.map_or(wake, |seen| seen.min(wake)));
            }
        }
        // The first due armed job that wakes its host (DESIGN 15-setting-primitive, stage 0.2).
        if let Some(at) = self.schedule_wake_at()? {
            earliest = Some(earliest.map_or(at, |seen| seen.min(at)));
        }
        Ok(earliest)
    }

    /// One pass of the runner within `deadline`, and its report. A handle's first pass arms every
    /// cadence job from its key's value in force and asks for the jobs that run at each start; the
    /// owner's pass asks for every cadence job, so each runs now and goes on from now.
    fn housekeeping_pass(
        &self,
        asked: Asked,
        deadline: &Deadline,
        access: &AccessSnapshot,
    ) -> Result<HousekeepingReport> {
        let started_at = self.now_recorded_at();
        {
            // The arming and the requests run under the pass lock, so a second pass of one handle
            // waits for them; the flag is set once both are done, so an arming or a request that
            // fails or panics is made again at the next pass. The runner takes the same lock
            // before its writes, so the lock order is unchanged.
            let mut passes = self
                .housekeeping
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !passes.first_pass_done {
                // The requests are durable: a pass the budget cuts short leaves them for the next.
                crate::schedule::arm_setting_jobs(self, is_cadence_job)?;
                crate::schedule::request_runs(self, |spec| spec.at_open)?;
                passes.first_pass_done = true;
            }
        }
        if asked == Asked::All {
            crate::schedule::request_runs(self, is_cadence_job)?;
        }
        let runs = self.run_due_until(&JobPass { deadline, access })?.runs;
        self.sweep_report(started_at, &runs, None)
    }

    /// The report of a pass that started at `started_at` and made `runs`: one row per sweep, or
    /// only `only`'s. A sweep starts at most once a pass, and its row reports that run; one the
    /// pass did not run is not due yet, or was left for a later pass.
    fn sweep_report(
        &self,
        started_at: u64,
        runs: &[JobRun],
        only: Option<HousekeepingSweep>,
    ) -> Result<HousekeepingReport> {
        let txn = self.store.env.read_txn()?;
        let mut sweeps = Vec::new();
        for sweep in HousekeepingSweep::ALL {
            if only.is_some_and(|only| only != sweep) {
                continue;
            }
            let outcome = match sweep.runner() {
                Runner::Host(reason) => SweepOutcome::HostOnly { reason },
                Runner::Engine => {
                    let job = jobs::job_code(sweep);
                    match runs.iter().rev().find(|run| run.job == job).and_then(ran) {
                        Some(outcome) => outcome,
                        None => {
                            match crate::schedule::due_at_in_txn(&self.store, &txn, &job, None)? {
                                Some(due_at) if due_at > started_at => {
                                    SweepOutcome::NotDue { due_at }
                                }
                                _ => SweepOutcome::OutOfBudget,
                            }
                        }
                    }
                }
            };
            sweeps.push(SweepReport { sweep, outcome });
        }
        Ok(HousekeepingReport { started_at, sweeps })
    }
}

/// A sweep's report row for a run of its job, or `None` for one that never started (an
/// interrupted run found and backed off, which the due time reports).
fn ran(run: &JobRun) -> Option<SweepOutcome> {
    Some(match run.outcome {
        JobOutcome::Done | JobOutcome::ItemsFailed => SweepOutcome::Ran {
            work: run.sweep_work.clone()?,
            complete: true,
        },
        JobOutcome::More => SweepOutcome::Ran {
            work: run.sweep_work.clone()?,
            complete: false,
        },
        JobOutcome::Failed { .. } => SweepOutcome::Failed {
            kind: run.error_kind.unwrap_or(ErrorKind::InvariantViolation),
        },
        JobOutcome::Panicked => SweepOutcome::Panicked,
        JobOutcome::Interrupted
        | JobOutcome::Lapsed
        | JobOutcome::Withdrawn
        | JobOutcome::UnknownJob => return None,
    })
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

fn prune_hook_feeds_once(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    if let Err(error) =
        crate::runtime_hooks::prune_hook_feeds(vault, crate::runtime_hooks::HOOK_PASS_ENTRIES)
    {
        tracing::warn!(%error, "housekeeping: passed hook feed rows wait for the next pass");
    }
}

/// Feed turn programs are released after the runner, which ran the due timer
/// programs beside the watcher ticks (untangle slice 6.8c; stage 5b-3), and
/// every wake they owe is admitted in the same pass, unless the host asked the
/// pass to stop. Its failures are logged and never fail the pass.
fn release_turn_program_wakes(vault: &Vault, deadline: &Deadline) {
    if deadline.stopped() {
        return;
    }
    crate::dreamer_runner::release_program_wakes(vault, vault.now_recorded_at());
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
