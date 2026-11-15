//! The engine's 19 sweeps as jobs of the one runner (DESIGN 15-setting-primitive, stage 5a).
//!
//! Each engine sweep is one [`JobSpec`] whose trigger is its cadence key
//! ([`super::setting_keys`]): the engine arms it at a handle's first pass and in the write that
//! changes the key, and the runner runs it when due, retries it after the backoff (60 s, doubling,
//! capped at the smaller of its cadence and an hour) and keeps its cursor between pages. No sweep
//! wakes a stopped vault for its cadence: the deadlines doors noted wake it
//! ([`crate::Vault::housekeeping_wake_at`]). A noted deadline is a row of its sweep's deadline job
//! (`housekeeping.<sweep>.deadline`, stage 5b), a one-time job at the deadline.
//!
//! One run of a sweep:
//! - a sweep starts at most once in a pass ([`JobSpec::once_per_pass`]), as it did before: a run
//!   that stopped at its bound is due again at once and goes on at the next pass;
//! - the deadlines it covers are those noted before it started and due by then; the write that
//!   records a run that finished with nothing failed disarms them. A deadline whose time comes
//!   before a run covered it runs: it makes the sweep due by then, and waits for the sweep's next
//!   due time;
//! - an unfinished walk keeps in its cursor whether an earlier page left items, and answers
//!   [`Ran::ItemsFailed`] at its end if one did;
//! - the erasure sweep runs as the owner's when its run answers a "run now" (the owner's
//!   `housekeeping_all`, or the owner's `vault.schedules.run`), and an owner's run that left a
//!   window uncompacted is retried as the owner's; while an obligation waits it is due again
//!   an hour after its last run ended, or at once when that hour has passed.

use super::{HousekeepingSweep, SweepWork, sweeps, wake};
use crate::Vault;
use crate::deletion::{HARD_ERASE_SWEEP_PREFIX, WITHDRAWN_GENERATION_SWEEP_PREFIX};
use crate::error::{Error, Result};
use crate::schedule::{
    ArmBy, Armed, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran, When,
};
use crate::store::Store;

/// The prefix of every sweep job's code: `housekeeping.<the sweep's code>`.
const JOB_PREFIX: &str = "housekeeping.";

/// While an erasure obligation waits, the erasure sweep runs at least this often, whatever its
/// cadence.
pub(super) const HARD_ERASE_BUSY_EVERY: u64 = 60 * 60;

/// The cursor's first byte: an earlier page of this walk left items.
const CURSOR_ITEMS_FAILED: u8 = 1;
/// The cursor's first byte: the sweep's own cursor follows.
const CURSOR_SWEEP: u8 = 2;

macro_rules! deadline_jobs {
    ($($(#[doc = $doc:literal])* $job:ident = $code:literal, wakes_host: $wakes:literal;)*) => {$(
        $(#[doc = $doc])*
        pub(crate) static $job: JobSpec = JobSpec {
            code: $code,
            when: When::PerArming,
            arm_by: ArmBy::Engine,
            late: Late::Run,
            retry_first_secs: RETRY_FIRST_SECS,
            retry_cap_secs: None,
            wakes_host: $wakes,
            at_open: false,
            once_per_pass: true,
            run: run_deadline_job,
        };
    )*};
}

deadline_jobs! {
    /// A secret lease's expiry; it wakes a stopped vault.
    SECRET_LEASE_EXPIRY_DEADLINE_JOB = "housekeeping.secret_lease_expiry.deadline", wakes_host: true;
    /// A critical confirm's window; it wakes a stopped vault.
    CRITICAL_CONFIRM_EXPIRY_DEADLINE_JOB = "housekeeping.critical_confirm_expiry.deadline", wakes_host: true;
    /// A voice print's retention deadline; it wakes a stopped vault.
    VOICE_PRINT_RETENTION_DEADLINE_JOB = "housekeeping.voice_print_retention.deadline", wakes_host: true;
    /// A shared act's window; it wakes a stopped vault.
    SHARED_ACT_MATURITY_DEADLINE_JOB = "housekeeping.shared_act_maturity.deadline", wakes_host: true;
    /// A live-body edit whose anchored comments must follow at the next running-host pass.
    ANNOTATION_BODY_ANCHORS_DEADLINE_JOB = "housekeeping.annotation_body_anchors.deadline", wakes_host: false;
}

/// The deadline job of `sweep`, or `None` for a sweep no door notes deadlines for.
pub(crate) fn deadline_job(sweep: HousekeepingSweep) -> Option<&'static JobSpec> {
    match sweep {
        HousekeepingSweep::SecretLeaseExpiry => Some(&SECRET_LEASE_EXPIRY_DEADLINE_JOB),
        HousekeepingSweep::CriticalConfirmExpiry => Some(&CRITICAL_CONFIRM_EXPIRY_DEADLINE_JOB),
        HousekeepingSweep::VoicePrintRetention => Some(&VOICE_PRINT_RETENTION_DEADLINE_JOB),
        HousekeepingSweep::SharedActMaturity => Some(&SHARED_ACT_MATURITY_DEADLINE_JOB),
        HousekeepingSweep::AnnotationBodyAnchors => Some(&ANNOTATION_BODY_ANCHORS_DEADLINE_JOB),
        _ => None,
    }
}

/// The sweep whose deadline job's code is `job`.
fn deadline_sweep_of(job: &str) -> Option<HousekeepingSweep> {
    HousekeepingSweep::ALL
        .into_iter()
        .find(|sweep| deadline_job(*sweep).is_some_and(|spec| spec.code == job))
}

macro_rules! sweep_jobs {
    ($($(#[doc = $doc:literal])* $job:ident = $code:literal, $key:ident, at_open: $at_open:literal;)*) => {$(
        $(#[doc = $doc])*
        pub(crate) static $job: JobSpec = JobSpec {
            code: $code,
            when: When::Setting(&super::setting_keys::$key),
            arm_by: ArmBy::Engine,
            late: Late::Run,
            retry_first_secs: RETRY_FIRST_SECS,
            retry_cap_secs: None,
            wakes_host: false,
            at_open: $at_open,
            once_per_pass: true,
            run: run_sweep_job,
        };
    )*};
}

sweep_jobs! {
    /// Secret leases past their expiry.
    SECRET_LEASE_EXPIRY_JOB = "housekeeping.secret_lease_expiry", SWEEP_SECRET_LEASE_EXPIRY, at_open: false;
    /// Critical confirms past their window.
    CRITICAL_CONFIRM_EXPIRY_JOB = "housekeeping.critical_confirm_expiry", SWEEP_CRITICAL_CONFIRM_EXPIRY, at_open: false;
    /// Symbol-lease holds past their expiry.
    SYMBOL_LEASE_EXPIRY_JOB = "housekeeping.symbol_lease_expiry", SWEEP_SYMBOL_LEASE_EXPIRY, at_open: false;
    /// Voice prints past their retention deadline.
    VOICE_PRINT_RETENTION_JOB = "housekeeping.voice_print_retention", SWEEP_VOICE_PRINT_RETENTION, at_open: false;
    /// Signing documents past their window.
    ESIGN_EXPIRY_JOB = "housekeeping.esign_expiry", SWEEP_ESIGN_EXPIRY, at_open: false;
    /// Missed signing seals.
    ESIGN_SEAL_BACKSTOP_JOB = "housekeeping.esign_seal_backstop", SWEEP_ESIGN_SEAL_BACKSTOP, at_open: false;
    /// Overdue open commitments.
    COMMITMENT_LAPSE_JOB = "housekeeping.commitment_lapse", SWEEP_COMMITMENT_LAPSE, at_open: false;
    /// Staged retirements and gate decisions past the owner's horizon; also at each start.
    GATE_DECISION_RETENTION_JOB = "housekeeping.gate_decision_retention", SWEEP_GATE_DECISION_RETENTION, at_open: true;
    /// Queued erasure obligations.
    HARD_ERASE_SWEEP_JOB = "housekeeping.hard_erase_sweep", SWEEP_HARD_ERASE_SWEEP, at_open: false;
    /// Cached graph walks past the longest serve window.
    PPR_CACHE_EVICTION_JOB = "housekeeping.ppr_cache_eviction", SWEEP_PPR_CACHE_EVICTION, at_open: false;
    /// Shared acts whose window has passed.
    SHARED_ACT_MATURITY_JOB = "housekeeping.shared_act_maturity", SWEEP_SHARED_ACT_MATURITY, at_open: false;
    /// The queued historical secret lift run.
    SECRET_LIFT_HISTORY_JOB = "housekeeping.secret_lift_history", SWEEP_SECRET_LIFT_HISTORY, at_open: false;
    /// Owed claim VAD consolidations; also at each start.
    CLAIM_VAD_DEBT_JOB = "housekeeping.claim_vad_debt", SWEEP_CLAIM_VAD_DEBT, at_open: true;
    /// Found-key notices left due.
    FOUND_KEY_NOTICES_JOB = "housekeeping.found_key_notices", SWEEP_FOUND_KEY_NOTICES, at_open: false;
    /// Whole-body line indexes reads found missing.
    BODY_LINE_INDEX_REBUILD_JOB = "housekeeping.body_line_index_rebuild", SWEEP_BODY_LINE_INDEX_REBUILD, at_open: false;
    /// Anchored comments following their live body; also at each start.
    ANNOTATION_BODY_ANCHORS_JOB = "housekeeping.annotation_body_anchors", SWEEP_ANNOTATION_BODY_ANCHORS, at_open: true;
    /// Sealed drafter corpora and training examples past their bound; also at each start.
    DRAFTER_CORPUS_SWEEP_JOB = "housekeeping.drafter_corpus_sweep", SWEEP_DRAFTER_CORPUS_SWEEP, at_open: true;
    /// Model pack retirement notices and moves.
    MODEL_PACK_RETIREMENT_JOB = "housekeeping.model_pack_retirement", SWEEP_MODEL_PACK_RETIREMENT, at_open: false;
    /// The OAuth server's rows past their lifetime.
    OAUTH_EXPIRY_JOB = "housekeeping.oauth_expiry", SWEEP_OAUTH_EXPIRY, at_open: false;
}

/// The code of `sweep`'s job.
pub(crate) fn job_code(sweep: HousekeepingSweep) -> String {
    format!("{JOB_PREFIX}{}", sweep.code())
}

/// The sweep a job's code names, or `None` for a job that is no sweep.
pub(super) fn sweep_of(job: &str) -> Option<HousekeepingSweep> {
    let code = job.strip_prefix(JOB_PREFIX)?;
    HousekeepingSweep::ALL
        .into_iter()
        .find(|sweep| sweep.code() == code)
}

/// Makes `sweep`'s job due no later than `at`, inside the caller's write: a door noted a deadline
/// it must run by. A job backing off keeps its backoff; a job not armed yet is armed due at once
/// by the next first pass.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn sweep_due_by_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    sweep: HousekeepingSweep,
    at: u64,
) -> Result<()> {
    crate::schedule::due_by_in_txn(store, txn, &job_code(sweep), None, at)
}

/// Makes the erasure sweep due an hour after its last run ended, or at once when that hour has
/// passed, inside the write that queues an obligation: the rule it kept before stage 5a, so an
/// obligation queued long after a run never waits another hour.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_obligation_queued_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let job = job_code(HousekeepingSweep::HardEraseSweep);
    let Some(last_end) = crate::schedule::finished_at_in_txn(store, txn, &job, None)? else {
        return Ok(());
    };
    let now = crate::ports::recorded_at_in_txn(store, txn)?;
    crate::schedule::due_by_in_txn(
        store,
        txn,
        &job,
        None,
        now.max(last_end.saturating_add(HARD_ERASE_BUSY_EVERY)),
    )
}

/// One run of the sweep `armed.job` names.
fn run_sweep_job(vault: &Vault, armed: &Armed, pass: &JobPass<'_>) -> Result<JobResult> {
    let sweep = sweep_of(armed.job).ok_or(Error::InvariantViolation(
        "a housekeeping job names no sweep",
    ))?;
    let start = vault.now_recorded_at();
    let (earlier_failed, cursor) = read_cursor(armed.cursor.as_deref());
    // The deadlines this run covers: noted before it started and due by then. A deadline noted
    // while it runs stays for the next run.
    let covered = wake::due_by(vault, sweep, start).unwrap_or_default();
    #[cfg(oneiron_test_support)]
    crate::test_doors::schedule::note_planted_deadline(vault, sweep)?;
    #[cfg(test)]
    match super::tests::injected(sweep) {
        Some(super::tests::Injected::Fail) => {
            return Err(Error::InvariantViolation("test: an injected sweep failure"));
        }
        Some(super::tests::Injected::Panic | super::tests::Injected::Crash) => {
            panic!("test: an injected sweep panic")
        }
        None => {}
    }
    let run = sweeps::run(
        vault,
        sweep,
        start,
        pass.deadline,
        cursor,
        armed.requested,
        pass.access,
    )?;
    // An owner's erasure run that left a window uncompacted (a caller held it, a write raced it,
    // its cut was not proved, or a legal hold kept it) has not answered the owner: it is retried
    // as the owner's, after the backoff.
    let owner_left = armed.requested
        && matches!(run.work, SweepWork::HardErase(work)
            if work.windows_deferred_live > 0
                || work.windows_deferred_raced > 0
                || work.windows_deferred_unproved > 0
                || work.windows_deferred_held > 0);
    let items_failed = earlier_failed || run.work.items_failed() > 0 || owner_left;
    let mut served = Vec::new();
    let ran = if !run.complete {
        Ran::More {
            cursor: write_cursor(items_failed, run.cursor.as_deref()),
        }
    } else if items_failed {
        Ran::ItemsFailed
    } else {
        // A walk that began before this run covers the deadlines due by when it began. A
        // deadline left behind runs at its time and waits for the run that covers it.
        served = wake::served(sweep, covered, run.covered_until);
        Ran::Done
    };
    let due_by = match ran {
        Ran::Done => owed_at(vault, sweep)?,
        _ => None,
    };
    Ok(JobResult {
        ran,
        due_by,
        sweep_work: Some(run.work),
        served,
    })
}

/// When a sweep that ran to its end owes work again before its next occurrence: for the erasure
/// sweep, within the hour while an obligation waits. A deadline a door noted that this run did not
/// cover is a row of its own, due at its time.
fn owed_at(vault: &Vault, sweep: HousekeepingSweep) -> Result<Option<u64>> {
    if sweep != HousekeepingSweep::HardEraseSweep || !erase_obligation_waiting(vault)? {
        return Ok(None);
    }
    Ok(Some(
        vault
            .now_recorded_at()
            .saturating_add(HARD_ERASE_BUSY_EVERY),
    ))
}

/// One run of a deadline no run of its sweep covered by its time: the pull its note made was
/// refused (the sweep was backing off or running), a run of the sweep ended before it came, or
/// the sweep's walk began before it. It makes the sweep due by now where its backoff allows, and
/// is due again when the sweep is next due, until the sweep's run that covers it disarms it.
fn run_deadline_job(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    let sweep = deadline_sweep_of(armed.job)
        .ok_or(Error::InvariantViolation("a deadline job names no sweep"))?;
    let job = job_code(sweep);
    let due = vault.with_write_txn_grouped(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        crate::schedule::due_by_in_txn(&vault.store, txn, &job, None, now)?;
        Ok(crate::schedule::due_at_in_txn(&vault.store, txn, &job, None)?.unwrap_or(now))
    })?;
    Ok(JobResult {
        due_by: Some(due),
        ..JobResult::of(Ran::Done)
    })
}

/// Whether any erasure obligation (an `h:` row, or a `hw:` withdrawn generation's) is queued.
pub(super) fn erase_obligation_waiting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for prefix in [HARD_ERASE_SWEEP_PREFIX, WITHDRAWN_GENERATION_SWEEP_PREFIX] {
        let mut rows = vault.store.sync_queue.prefix_iter(&txn, prefix)?;
        if rows.next().transpose()?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The job cursor of an unfinished walk: one flag byte, then the sweep's own cursor.
fn write_cursor(items_failed: bool, sweep: Option<&[u8]>) -> Vec<u8> {
    let mut flags = 0;
    if items_failed {
        flags |= CURSOR_ITEMS_FAILED;
    }
    if sweep.is_some() {
        flags |= CURSOR_SWEEP;
    }
    let mut cursor = vec![flags];
    cursor.extend_from_slice(sweep.unwrap_or_default());
    cursor
}

/// Whether an earlier page of the walk left items, and the sweep's own cursor.
fn read_cursor(cursor: Option<&[u8]>) -> (bool, Option<&[u8]>) {
    match cursor.and_then(<[u8]>::split_first) {
        Some((flags, sweep)) => (
            flags & CURSOR_ITEMS_FAILED != 0,
            (flags & CURSOR_SWEEP != 0).then_some(sweep),
        ),
        None => (false, None),
    }
}
