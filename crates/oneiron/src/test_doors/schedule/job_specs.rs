//! The `test.*` job kinds the Schedule primitive's tests arm.

use super::{
    count, run_answer, run_bounded, run_cadence, run_count, run_fail, run_items, run_paged,
    run_seen,
};
use crate::Vault;
use crate::error::Result;
use crate::schedule::{
    ArmBy, Armed, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran, Trigger, When,
};

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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
    drive: crate::schedule::Drive::Runner,
    run: run_bounded,
};

/// A one-time job the engine arms (`Trigger::At`); each run is seen and answers the `due_by`
/// [`super::set_cadence_due_by`] set (stage 5b-1).
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
    runs_here: |_vault, _txn| Ok(true),
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
    runs_here: |_vault, _txn| Ok(true),
    drive: crate::schedule::Drive::Runner,
    run: run_rearm,
};
