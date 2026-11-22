//! Doors for census L1-18, the Coach's two retrieval-tuning loops
//! (ARCH-0053 #tune-retrieval): run one nightly `coach.retrieval_tune`
//! attempt the way the wake driver runs a maintenance job, lease the next
//! host-run Coach job, and import a library skill from the default hub at a
//! local folder fixture's commit.

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, COACH_RETRIEVAL_TUNE_FACET, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext, WakePassDeadline};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

fn admission(now: u64) -> AdmitDreamerAttempt {
    AdmitDreamerAttempt {
        lease_owner: "test-door".to_owned(),
        now,
        budget_id: "wake".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        started_milestone: None,
    }
}

/// Queues one `coach.retrieval_tune` attempt as a Timer wake does, admits it
/// and runs it through the maintenance dispatch. Returns the attempt's id
/// once the run completes; any other end is an error naming it.
pub fn run_retrieval_tune(vault: &Vault, now: u64) -> Result<AttemptId> {
    let store = DreamerRunnerStore::new(vault);
    let wake_key = format!("census-l1-18.retrieval_tune:{now}");
    vault.with_write_txn(|txn| {
        store
            .enqueue_coach_retrieval_tune_in_txn(txn, None, Some(&wake_key), None, now)
            .map(|_| ())
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_maintenance(admission(now))?
    else {
        return Err(Error::InvalidConfig(
            "the retrieval tune was not admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != COACH_RETRIEVAL_TUNE_FACET {
        return Err(Error::InvalidConfig(format!(
            "the maintenance lane admitted {} before the retrieval tune",
            admitted.status.payload.attempt_type
        )));
    }
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let execution = crate::dreamer_runner::maintenance::execute(
        &admitted,
        &WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: "wake",
            now_ms: now.saturating_mul(1000),
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
        None,
    )?;
    if !matches!(execution, DreamerAttemptExecution::Completed { .. }) {
        return Err(Error::InvalidConfig(format!(
            "the retrieval tune did not complete: {execution:?}"
        )));
    }
    Ok(admitted.status.attempt.id)
}

/// Leases the next host-run Coach job as a host Coach does, or `None` when
/// the Coach host queue is empty. Its facet is
/// `status.payload.attempt_type` and its parent `status.payload.parent_attempt`.
pub fn next_coach_host_attempt(vault: &Vault, now: u64) -> Result<Option<DreamerAdmittedAttempt>> {
    match DreamerRunnerStore::new(vault).admit_next_coach_host_job(admission(now))? {
        DreamerAdmissionOutcome::Admitted(admitted) => Ok(Some(*admitted)),
        DreamerAdmissionOutcome::Empty => Ok(None),
        DreamerAdmissionOutcome::BudgetExhausted(_) => Err(Error::InvalidConfig(
            "the wake budget refused the Coach host job".into(),
        )),
    }
}

/// The owner's library import of `subtree` from the default hub at `commit`,
/// through the door [`Vault::import_default_hub_skill`] runs at the released
/// commit. A test points the default hub at a local folder fixture, whose
/// commit cannot be the released one.
pub fn import_default_hub_skill_at(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    subtree: &str,
    commit: &str,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    vault.import_default_hub_skill_at_commit(owner, subtree, commit, occurred, learned_at)
}
