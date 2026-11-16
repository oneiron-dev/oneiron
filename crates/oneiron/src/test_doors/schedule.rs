//! The job kinds and doors the Schedule primitive's tests use (DESIGN 15-setting-primitive,
//! stages 0.2, 5a-1 and 5a-2). They exist only under `--cfg oneiron_test_support`; no engine code
//! arms them.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::model_pack::AccessSnapshot;
use crate::schedule::{
    ArmBy, Armed, JobOutcome, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran,
    ScheduleView, Trigger, When,
};
use crate::store::housekeeping_schedule::{HousekeepingBudget, HousekeepingSweep};

/// Every test run, by job code and subject.
static RUNS: Mutex<BTreeMap<(&'static str, Option<EntityId>), u64>> = Mutex::new(BTreeMap::new());

fn count(armed: &Armed) -> u64 {
    let mut runs = RUNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = runs.entry((armed.job, armed.subject)).or_default();
    *entry += 1;
    *entry
}

/// How many times `job` about `subject` has run.
#[must_use]
pub fn runs(job: &str, subject: Option<EntityId>) -> u64 {
    RUNS.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|((code, about), _)| *code == job && *about == subject)
        .map(|(_, runs)| *runs)
        .sum()
}

fn run_count(_vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    count(armed);
    Ok(JobResult::of(Ran::Done))
}

fn run_fail(_vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    count(armed);
    Ok(JobResult::of(Ran::Failed))
}

/// Three pages: each run takes one and answers "more" until the third.
fn run_paged(_vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    count(armed);
    let page = armed
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.first().copied())
        .unwrap_or(0)
        + 1;
    Ok(JobResult::of(if page >= 3 {
        Ran::Done
    } else {
        Ran::More { cursor: vec![page] }
    }))
}

/// One run of a stage 5a-1 test job, as its test reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRun {
    /// Whether the run answered a "run now".
    pub requested: bool,
    /// The cursor it went on from.
    pub cursor: Option<Vec<u8>>,
}

/// The vault a run ran in, by its directory: the stage 5a-1 jobs have no subject, so their
/// tests, which run side by side, keep their records apart by vault.
fn vault_of(vault: &Vault) -> PathBuf {
    vault.store.env.path().to_path_buf()
}

/// Every run of a stage 5a-1 test job, by vault and job code, in run order.
static SEEN: Mutex<BTreeMap<(PathBuf, &'static str), Vec<SeenRun>>> = Mutex::new(BTreeMap::new());

/// The `due_by` the cadence job and the one-time job answer, by vault.
static CADENCE_DUE_BY: Mutex<BTreeMap<PathBuf, u64>> = Mutex::new(BTreeMap::new());

/// A deadline the next run of a sweep notes while it runs, by vault and sweep.
static PLANTED_DEADLINES: Mutex<BTreeMap<(PathBuf, &'static str), u64>> =
    Mutex::new(BTreeMap::new());

/// Records a run; answers how many runs of its job this vault has made, this one included.
fn record(vault: &Vault, armed: &Armed) -> usize {
    let mut seen = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let runs = seen.entry((vault_of(vault), armed.job)).or_default();
    runs.push(SeenRun {
        requested: armed.requested,
        cursor: armed.cursor.clone(),
    });
    runs.len()
}

/// The runs `job` made in `vault`, in order.
#[must_use]
pub fn seen(vault: &Vault, job: &str) -> Vec<SeenRun> {
    SEEN.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|((at, code), _)| *at == vault_of(vault) && *code == job)
        .flat_map(|(_, runs)| runs.iter().cloned())
        .collect()
}

/// The cadence job and the one-time job (`test.due_by`) in `vault` answer `due_by` from their
/// next run on.
pub fn set_cadence_due_by(vault: &Vault, due_by: Option<u64>) {
    let mut due = CADENCE_DUE_BY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match due_by {
        Some(at) => due.insert(vault_of(vault), at),
        None => due.remove(&vault_of(vault)),
    };
}

fn run_cadence(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    record(vault, armed);
    let due_by = CADENCE_DUE_BY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&vault_of(vault))
        .copied();
    Ok(JobResult {
        due_by,
        ..JobResult::of(Ran::Done)
    })
}

/// Two pages: the first answers "more", the second reaches the end with items left.
fn run_items(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    record(vault, armed);
    Ok(JobResult::of(match armed.cursor {
        None => Ran::More { cursor: vec![1] },
        Some(_) => Ran::ItemsFailed,
    }))
}

/// Fails on its first run, and is done on every later one.
fn run_answer(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    Ok(JobResult::of(if record(vault, armed) == 1 {
        Ran::Failed
    } else {
        Ran::Done
    }))
}

fn run_seen(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    record(vault, armed);
    Ok(JobResult::of(Ran::Done))
}

/// Always stops at its bound with work left, from the same cursor: a drain that may find the same
/// items again.
fn run_bounded(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    record(vault, armed);
    Ok(JobResult::of(Ran::More { cursor: vec![0] }))
}

/// A job an actor arms; each run counts, and it wakes a stopped vault.
pub static TEST_COUNT: JobSpec = JobSpec {
    code: "test.count",
    when: When::PerArming,
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: true,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_count,
};

/// A job that always fails.
pub static TEST_FAIL: JobSpec = JobSpec {
    code: "test.fail",
    when: When::PerArming,
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_fail,
};

/// A job whose work takes three runs.
pub static TEST_PAGED: JobSpec = JobSpec {
    code: "test.paged",
    when: When::PerArming,
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_paged,
};

/// A job only the engine arms.
pub static TEST_ENGINE: JobSpec = JobSpec {
    code: "test.engine",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_count,
};

/// A job that makes no sense more than ten minutes late.
pub static TEST_LAPSE: JobSpec = JobSpec {
    code: "test.lapse",
    when: When::PerArming,
    arm_by: ArmBy::Actor,
    late: Late::Lapse { after_secs: 600 },
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_count,
};

/// A job whose cadence is the test key `test.job_cadence`.
pub static TEST_CADENCE: JobSpec = JobSpec {
    code: "test.cadence",
    when: When::Setting(&crate::test_doors::setting_keys::TEST_JOB_CADENCE),
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_cadence,
};

/// A paged job whose walk ends with items left.
pub static TEST_ITEMS: JobSpec = JobSpec {
    code: "test.items",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_items,
};

/// A job that also runs at the first pass of every handle.
pub static TEST_OPEN: JobSpec = JobSpec {
    code: "test.open",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: true,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_seen,
};

/// A job that fails once, then is done.
pub static TEST_ANSWER: JobSpec = JobSpec {
    code: "test.answer",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_answer,
};

/// A drain that starts once a pass, as the engine's sweeps do (stage 5a-2).
pub static TEST_ONCE: JobSpec = JobSpec {
    code: "test.once",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: true,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_bounded,
};

/// A one-time job the engine arms (`Trigger::At`); each run is seen and answers the `due_by`
/// [`set_cadence_due_by`] set (stage 5b-1).
pub static TEST_DUE_BY: JobSpec = JobSpec {
    code: "test.due_by",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_cadence,
};

/// How far past its due time the first run of [`TEST_REARM`] about a subject arms its own row
/// again.
pub const TEST_REARM_AFTER_SECS: u64 = 3_600;

/// The first run about a subject arms its own row again, at its due time plus
/// [`TEST_REARM_AFTER_SECS`], in its own write while it runs, then answers done with no `due_by`;
/// every later run only counts. A TASK rewrite that moves a waiting tick's due time while the
/// tick runs is the engine's case (OPUS-SETTING's review F2 of stage 5b-3).
fn run_rearm(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    if count(armed) == 1 {
        let at = armed.due_at.saturating_add(TEST_REARM_AFTER_SECS);
        vault.with_write_txn_grouped(|txn| {
            crate::schedule::arm_in_txn(
                &vault.store,
                txn,
                &TEST_REARM,
                armed.subject,
                Trigger::At { at },
            )
        })?;
    }
    Ok(JobResult::of(Ran::Done))
}

/// A one-time job the engine arms (`Trigger::At`) whose first run arms its own row again
/// ([`run_rearm`]; stage 5b-3).
pub static TEST_REARM: JobSpec = JobSpec {
    code: "test.rearm",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_rearm,
};

/// The next run of `sweep` in `vault` notes a deadline at `at` while it runs, after it listed
/// the deadlines it covers, as a door that writes during the run does (stage 5b-1).
pub fn note_deadline_during_next_run(vault: &Vault, sweep: HousekeepingSweep, at: u64) {
    PLANTED_DEADLINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((vault_of(vault), sweep.code()), at);
}

/// The hook a sweep's run calls once it listed the deadlines it covers: it notes the deadline
/// [`note_deadline_during_next_run`] planted for this run, if any.
///
/// # Errors
///
/// As the note.
pub(crate) fn note_planted_deadline(vault: &Vault, sweep: HousekeepingSweep) -> Result<()> {
    let planted = PLANTED_DEADLINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(vault_of(vault), sweep.code()));
    match planted {
        Some(at) => note_sweep_deadline(vault, sweep, at),
        None => Ok(()),
    }
}

/// Whether `spec` is one of these test job kinds (code `test.*`): the doors below take only
/// them, so the engine's own jobs never join a test's runs.
fn is_test_job(spec: &JobSpec) -> bool {
    spec.code.starts_with("test.")
}

/// The engine arms every test job whose cadence is a Setting key, as the host's first pass does.
///
/// # Errors
///
/// As the arming.
pub fn arm_cadence_jobs(vault: &Vault) -> Result<()> {
    crate::schedule::arm_setting_jobs(vault, is_test_job)
}

/// The engine asks for a run of every armed test job that runs at a handle's first pass; how
/// many.
///
/// # Errors
///
/// Storage errors.
pub fn request_at_open_runs(vault: &Vault) -> Result<usize> {
    crate::schedule::request_runs(vault, |spec| is_test_job(spec) && spec.at_open)
}

/// The engine asks for a run of every armed test job whose cadence is a Setting key; how many.
///
/// # Errors
///
/// Storage errors.
pub fn request_cadence_runs(vault: &Vault) -> Result<usize> {
    crate::schedule::request_runs(vault, |spec| {
        is_test_job(spec) && matches!(spec.when, When::Setting(_))
    })
}

/// Runs `job` about `subject` alone, now; its outcome, or `None` when it is not armed.
///
/// # Errors
///
/// Storage errors.
pub fn run_job_now(
    vault: &Vault,
    job: &str,
    subject: Option<EntityId>,
) -> Result<Option<JobOutcome>> {
    let deadline = HousekeepingBudget::unbounded().deadline();
    let access = AccessSnapshot::new();
    let pass = JobPass {
        deadline: &deadline,
        access: &access,
    };
    Ok(vault
        .run_job_now(job, subject, &pass)?
        .map(|run| run.outcome))
}

/// A door makes `job` about `subject` due by `at`, in its own write.
///
/// # Errors
///
/// Storage errors.
pub fn pull_due_forward(
    vault: &Vault,
    job: &str,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::schedule::due_by_in_txn(&vault.store, txn, job, subject, at)
    })
}

/// The write that queues an erasure obligation makes the erasure sweep due, here in its own
/// write and with no obligation queued: the pull alone (stage 5a-2).
///
/// # Errors
///
/// Storage errors.
pub fn pull_for_queued_erase_obligation(vault: &Vault) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::housekeeping::jobs::erase_obligation_queued_in_txn(&vault.store, txn)
    })
}

/// A run of `job` about `subject` started at `at` and never finished, as a crash or a kill leaves
/// it: its start marker, in its own write (stage 5a-2). Nothing when the job is not armed.
///
/// # Errors
///
/// Storage errors.
pub fn plant_start_marker(
    vault: &Vault,
    job: &str,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::schedule::plant_start_marker_in_txn(&vault.store, txn, job, subject, at)
    })
}

/// The codes of the job kinds whose cadence is a Setting key but which someone other than the
/// engine may arm; empty, since only the engine arms from a cadence key.
#[must_use]
pub fn cadence_jobs_not_engine_armed() -> Vec<&'static str> {
    crate::schedule::jobs()
        .filter(|spec| matches!(spec.when, When::Setting(_)) && spec.arm_by != ArmBy::Engine)
        .map(|spec| spec.code)
        .collect()
}

/// The codes of the job kinds whose cadence is a Setting key.
#[must_use]
pub fn cadence_jobs() -> Vec<&'static str> {
    crate::schedule::jobs()
        .filter(|spec| matches!(spec.when, When::Setting(_)))
        .map(|spec| spec.code)
        .collect()
}

/// A door notes that `sweep` has work due at `at`, in its own write, as the secret-lease, voice
/// print, critical-confirm and shared-act doors do (DESIGN 15-setting-primitive, stage 5a).
///
/// # Errors
///
/// Storage errors.
pub fn note_sweep_deadline(vault: &Vault, sweep: HousekeepingSweep, at: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::housekeeping::note_wake_in_txn(&vault.store, txn, sweep, at)
    })
}

/// When `job` about `subject` is next due, as the engine reads it.
///
/// # Errors
///
/// Storage errors.
pub fn due_at(vault: &Vault, job: &str, subject: Option<EntityId>) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    crate::schedule::due_at_in_txn(&vault.store, &txn, job, subject)
}

/// Fails its first run about a subject; every later run is done.
fn run_fail_once(_vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    Ok(JobResult::of(if count(armed) == 1 {
        Ran::Failed
    } else {
        Ran::Done
    }))
}

/// A job whose first run about a subject fails, and whose retry is done.
pub static TEST_FAIL_ONCE: JobSpec = JobSpec {
    code: "test.fail_once",
    when: When::PerArming,
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: false,
    runs_here: crate::schedule::any_node,
    drive: crate::schedule::Drive::Runner,
    run: run_fail_once,
};

/// The engine arms `job` about `subject`, as its own doors do.
///
/// # Errors
///
/// As the arming.
pub fn arm_as_engine(
    vault: &Vault,
    job: &str,
    subject: Option<EntityId>,
    trigger: Trigger,
) -> Result<ScheduleView> {
    vault.arm_schedule(None, job, subject, trigger)
}

/// Runs `act` while a housekeeping pass holds the schedule's runner, as a pass on another thread
/// holds it (stage 5b-4): a host loop's run of its own job's rows meets the held runner.
pub fn while_a_pass_holds_the_runner<T>(vault: &Vault, act: impl FnOnce() -> T) -> T {
    let _held = vault
        .housekeeping
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    act()
}

/// When `task`'s watcher tick is due while it still waits for it, or `None` once it ticked, for
/// a TASK with no due time, and for one closed before its tick (stage 5b-3): the tick a run of
/// `runtime_hooks.task_tick` releases.
///
/// # Errors
///
/// Storage errors.
pub fn task_tick_waiting(vault: &Vault, task: EntityId) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    crate::runtime_hooks::task_tick_waiting_in_txn(vault, &txn, task)
}

/// The paced verb line's job code (stage 5c-2).
pub const PACED_VERB_LINE: &str = "runtime_hooks.paced_verb_line";

/// Holds a call by `actor` in the paced line with no witness, its window opening at
/// `next_eligible_at` and its deadline at `deadline`, through the hold's own write of the row and
/// its line arming; answers its key. Its turn ends refused.
///
/// # Errors
///
/// Storage errors.
pub fn plant_paced_verb_call(
    vault: &Vault,
    actor: EntityId,
    next_eligible_at: u64,
    deadline: u64,
) -> Result<[u8; 16]> {
    vault.plant_paced_verb_call(actor, next_eligible_at, deadline)
}

/// Whether the planted paced call `key` still waits in the line: held, not ended.
///
/// # Errors
///
/// Storage errors.
pub fn paced_verb_call_waits(vault: &Vault, key: [u8; 16]) -> Result<bool> {
    vault.paced_verb_call_waits(key)
}

/// A call the next run of the paced verb line holds while it runs, by vault: its actor, the
/// opening of its window and its deadline.
static PLANTED_PACED_HOLDS: Mutex<BTreeMap<PathBuf, (EntityId, u64, u64)>> =
    Mutex::new(BTreeMap::new());

/// The next run of the paced verb line in `vault` holds a call by `actor` once it took its
/// turns and before it answers, its window opening at `next_eligible_at` and its deadline at
/// `deadline`, through the hold's own write: a hold that lands during a line run (stage 5c-2).
pub fn hold_during_next_line_run(
    vault: &Vault,
    actor: EntityId,
    next_eligible_at: u64,
    deadline: u64,
) {
    PLANTED_PACED_HOLDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(vault_of(vault), (actor, next_eligible_at, deadline));
}

/// The hook the paced verb line's run calls once it took its turns: it holds the call
/// [`hold_during_next_line_run`] planted for this run, if any.
///
/// # Errors
///
/// As the hold.
pub(crate) fn hold_planted_paced_call(vault: &Vault) -> Result<()> {
    let planted = PLANTED_PACED_HOLDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&vault_of(vault));
    match planted {
        Some((actor, next_eligible_at, deadline)) => vault
            .plant_paced_verb_call(actor, next_eligible_at, deadline)
            .map(drop),
        None => Ok(()),
    }
}

/// The engine disarms `job` about `subject`, as its own doors do: `false` when it was not armed.
///
/// # Errors
///
/// As the disarming.
pub fn disarm_as_engine(vault: &Vault, job: &str, subject: Option<EntityId>) -> Result<bool> {
    vault.disarm_schedule(None, job, subject)
}

/// The remote task poll job's code (stage 5c-2).
pub const REMOTE_TASK_POLL: &str = "outbound_intent_ledger.remote_task_poll";

/// Defers one Pending `email`/`send` row as a remote task its provider took, its handle keeping
/// how to poll it (a route credential, no session), through the ledger's own deferral write,
/// which schedules its first poll; `attempt` tells one test's rows apart, and `poll_after_secs`
/// is the provider's hint. Answers its intent id.
///
/// # Panics
///
/// When the row cannot be written or deferred.
#[must_use]
pub fn defer_pollable_remote_task(
    vault: &Vault,
    attempt: u8,
    poll_after_secs: Option<u64>,
) -> [u8; 32] {
    use crate::outbound_intent_ledger::{
        BudgetChargeMarker, BudgetClass, IntentLedgerRecord, OutboundCallRequest,
        RemoteTaskCredential, RemoteTaskHandle, RemoteTaskPoll, defer_record, force_sync,
        insert_pending_in_txn,
    };
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let request = OutboundCallRequest::new(
        crate::attempt_queue::AttemptId::from_bytes(&[attempt; 16]).expect("attempt id"),
        1,
        "email",
        "send",
        vec![attempt; 8],
        now_ms,
    );
    let marker = BudgetChargeMarker {
        key_ref: None,
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: now_ms,
    };
    let record = IntentLedgerRecord::pending(request, false, marker).expect("pending row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    insert_pending_in_txn(vault, &mut wtxn, &record).expect("insert the pending row");
    wtxn.commit().expect("commit the pending row");
    force_sync(vault).expect("sync the pending row");
    let handle = RemoteTaskHandle {
        id: format!("task-{attempt}"),
        poll_after_secs,
        poll: Some(RemoteTaskPoll {
            session: None,
            protocol: "2025-11-25".to_owned(),
            credential: RemoteTaskCredential::Route,
            form_elicitation: false,
        }),
    };
    defer_record(vault, record.id, handle, now_ms).expect("defer the row");
    record.id
}

/// The intent ids of the Deferred sends whose tasks are due a poll now, as the served host reads
/// them, at most 32.
///
/// # Panics
///
/// When the due list cannot be read.
#[must_use]
pub fn remote_tasks_due_now(vault: &Vault) -> Vec<[u8; 32]> {
    vault
        .remote_tasks_due(32)
        .expect("the due remote tasks")
        .into_iter()
        .map(|task| task.intent)
        .collect()
}

/// A poll that found `intent`'s task still running, as the served host records it now.
///
/// # Panics
///
/// When it cannot be recorded.
pub fn remote_task_polled_now(vault: &Vault, intent: &[u8; 32], poll_after_ms: Option<u64>) {
    vault
        .remote_task_polled(intent, poll_after_ms, "working")
        .expect("record the poll");
}

/// Makes the polls of `intents` due now, as the host does for a task whose parked question the
/// owner answered.
///
/// # Panics
///
/// When it cannot be written.
pub fn remote_task_polls_due_now(vault: &Vault, intents: &[[u8; 32]]) {
    vault
        .remote_task_polls_due_at(intents)
        .expect("make the polls due");
}

/// Settles `intent` by a poll that found its task ended unconfirmed.
///
/// # Panics
///
/// When it cannot be settled.
pub fn settle_remote_task_unconfirmed(vault: &Vault, intent: &[u8; 32]) {
    vault
        .settle_polled_remote_task(
            intent,
            crate::outbound_intent_ledger::RemoteTaskEnd::Unconfirmed,
        )
        .expect("settle the task");
}
