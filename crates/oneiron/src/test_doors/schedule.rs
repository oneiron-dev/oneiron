//! The job kinds and doors the Schedule primitive's tests use (DESIGN 15-setting-primitive,
//! stage 0.2). They exist only under `--cfg oneiron_test_support`; no engine code arms them.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::schedule::{ArmBy, Armed, JobSpec, Late, RETRY_FIRST_SECS, Ran, ScheduleView, Trigger};
use crate::store::housekeeping_schedule::Deadline;

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

fn run_count(_vault: &Vault, armed: &Armed, _deadline: &Deadline) -> Result<Ran> {
    count(armed);
    Ok(Ran::Done)
}

fn run_fail(_vault: &Vault, armed: &Armed, _deadline: &Deadline) -> Result<Ran> {
    count(armed);
    Ok(Ran::Failed)
}

/// Three pages: each run takes one and answers "more" until the third.
fn run_paged(_vault: &Vault, armed: &Armed, _deadline: &Deadline) -> Result<Ran> {
    count(armed);
    let page = armed
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.first().copied())
        .unwrap_or(0)
        + 1;
    Ok(if page >= 3 {
        Ran::Done
    } else {
        Ran::More { cursor: vec![page] }
    })
}

/// A job an actor arms; each run counts, and it wakes a stopped vault.
pub static TEST_COUNT: JobSpec = JobSpec {
    code: "test.count",
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: true,
    run: run_count,
};

/// A job that always fails.
pub static TEST_FAIL: JobSpec = JobSpec {
    code: "test.fail",
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    run: run_fail,
};

/// A job whose work takes three runs.
pub static TEST_PAGED: JobSpec = JobSpec {
    code: "test.paged",
    arm_by: ArmBy::Actor,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    run: run_paged,
};

/// A job only the engine arms.
pub static TEST_ENGINE: JobSpec = JobSpec {
    code: "test.engine",
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    run: run_count,
};

/// A job that makes no sense more than ten minutes late.
pub static TEST_LAPSE: JobSpec = JobSpec {
    code: "test.lapse",
    arm_by: ArmBy::Actor,
    late: Late::Lapse { after_secs: 600 },
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    run: run_count,
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
