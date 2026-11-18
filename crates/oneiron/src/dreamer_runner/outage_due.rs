//! The timed resume of provider-outage parks that carry a retry hint.
//!
//! A host door's outage park may carry the provider's retry hint ([`outage_park_reason`]). Each
//! such park arms one row of [`OUTAGE_RESUME_JOB`] about its attempt, at its parked time plus
//! the hint, in the write that parks it; the write that clears or replaces the park disarms it
//! (DESIGN 15-setting-primitive, stage 5b). The schedule's runner runs the rows due on the
//! host's housekeeping pass. A run resumes the park through the agent-run pump's owner-checked
//! idempotent resume door, which recovery and restart use too, so only one of them resumes it.
//! The resumed run's own next call probes the rested offer and parks again while it is still
//! unavailable. The job wakes no stopped vault: the park waits for its host, as before.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::model_pack::AccessSnapshot;
use crate::schedule::{
    ArmBy, Armed, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran, Trigger, When,
};
use crate::store::housekeeping_schedule::HousekeepingBudget;

use super::store::DreamerRunnerStore;
use super::types::DreamerParkedAttemptRecord;
use super::{AGENT_RUNS_PARK_OWNER, ParkOwnerClass, ParkResume, ParkResumer};

const OUTAGE_PARK_REASON: &str = "agent_run_provider_unavailable";

/// Each hinted outage park's timed resume: a one-time row about the parked attempt, armed at its
/// parked time plus the provider's retry hint. A run resumes the park in one write; a park its
/// run may not take yet stays armed.
pub(crate) static OUTAGE_RESUME_JOB: JobSpec = JobSpec {
    code: "dreamer_runner.outage_resume",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: true,
    runs_here: crate::schedule::any_node,
    run: run_outage_resume,
};

/// Encodes a host door's relative retry hint on its park. No hint means no
/// timed resume: recovery or restart still resumes the park.
pub fn outage_park_reason(retry_after: Option<u64>) -> String {
    retry_after.map_or_else(
        || OUTAGE_PARK_REASON.to_owned(),
        |seconds| format!("{OUTAGE_PARK_REASON}:retry_after={seconds}"),
    )
}

/// The provider's retry hint on a host-door outage park, if it carried one.
pub fn outage_retry_after(reason: &str) -> Option<u64> {
    reason
        .strip_prefix(OUTAGE_PARK_REASON)?
        .strip_prefix(":retry_after=")?
        .parse()
        .ok()
}

fn outage_due_at(record: &DreamerParkedAttemptRecord) -> Option<u64> {
    if !ParkResume::cause_may_resume(record.cause, ParkResumer::OutageSweep) {
        return None;
    }
    outage_retry_after(&record.reason)
        .map(|retry_after| record.parked_at.saturating_add(retry_after))
}

/// The schedule subject of the parked attempt `attempt`: its 16 bytes.
fn subject(attempt: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes())
}

/// Arms `record`'s timed resume at its hinted due time, in the writer that parks it. A park with
/// no hint, or one the outage resume never takes, arms nothing.
pub(crate) fn index_outage_due_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(at) = outage_due_at(record) else {
        return Ok(());
    };
    crate::schedule::arm_in_txn(
        &vault.store,
        wtxn,
        &OUTAGE_RESUME_JOB,
        Some(subject(record.attempt_id)?),
        Trigger::At { at },
    )
}

/// Disarms `record`'s timed resume, in the writer that clears or replaces the park.
pub(crate) fn unindex_outage_due_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    if outage_due_at(record).is_none() {
        return Ok(());
    }
    crate::schedule::disarm_in_txn(
        &vault.store,
        wtxn,
        OUTAGE_RESUME_JOB.code,
        Some(subject(record.attempt_id)?),
    )?;
    Ok(())
}

impl Vault {
    /// Runs the due rows of [`OUTAGE_RESUME_JOB`] now, ahead of the housekeeping pass: the
    /// resident pump's outage step, so a hinted park resumes on the pump's first pass after its
    /// hint rather than at the next tick. Returns how many rows it ran. While a housekeeping pass
    /// holds the runner it runs nothing and returns 0: that pass runs the due rows.
    ///
    /// # Errors
    ///
    /// Storage errors reading or writing the schedule; a run's own failure backs off on its row.
    pub fn resume_due_outage_parks(&self) -> Result<usize> {
        let deadline = HousekeepingBudget::unbounded().deadline();
        let access = AccessSnapshot::new();
        let pass = JobPass {
            deadline: &deadline,
            access: &access,
        };
        Ok(self
            .run_due_of(&[&OUTAGE_RESUME_JOB], &pass)?
            .map_or(0, |report| report.runs.len()))
    }
}

/// What one run of [`OUTAGE_RESUME_JOB`] decided about its park.
enum OutageRun {
    /// The park resumed; the resume disarmed the row in the same write.
    Resumed,
    /// The attempt, its park or its hint is gone, or the outage resume never takes the park:
    /// the row goes.
    Stale,
    /// Not this run's to take now: the try is not leased, the park's owner is one the outage
    /// resume does not serve, or the hint is not due yet. The row stays armed, due then.
    Later(u64),
}

/// Resumes the outage park `armed` is about once its hint is due, in one write, under the
/// agent-run pump's park owner: the only owner whose parks the outage resume takes. A failed
/// resume writes nothing and the runner tries the row again after its backoff.
fn run_outage_resume(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    let Some(subject) = armed.subject else {
        return Ok(JobResult::of(Ran::Done));
    };
    let attempt = AttemptId::from_bytes(subject.as_bytes())?;
    let store = DreamerRunnerStore::new(vault);
    let outcome = vault.with_write_txn(|wtxn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        let Some((status, park)) = store.status_with_park_in_txn(wtxn, attempt)? else {
            return Ok(OutageRun::Stale);
        };
        if !matches!(status.attempt.state, AttemptState::Leased) {
            return Ok(OutageRun::Later(armed.due_at));
        }
        let Some(park) = park else {
            return Ok(OutageRun::Stale);
        };
        if !ParkResume::owner_may_resume(
            ParkOwnerClass::of(&park.park_owner),
            ParkResumer::OutageSweep,
        ) {
            return Ok(OutageRun::Later(armed.due_at));
        }
        if !park.resumable_by(ParkResumer::OutageSweep) {
            return Ok(OutageRun::Stale);
        }
        match outage_due_at(&park) {
            None => return Ok(OutageRun::Stale),
            Some(at) if at > now => return Ok(OutageRun::Later(at)),
            Some(_) => {}
        }
        Ok(
            match store.resume_parked_in_txn(wtxn, attempt, AGENT_RUNS_PARK_OWNER, now)? {
                Some(_) => OutageRun::Resumed,
                None => OutageRun::Stale,
            },
        )
    })?;
    let due_by = match outcome {
        OutageRun::Resumed => {
            vault.store.notify_attempt_observers();
            // The deadline lane arms the queued try at once.
            vault.store.notify_proactivity_changes();
            None
        }
        OutageRun::Stale => None,
        OutageRun::Later(at) => Some(at),
    };
    Ok(JobResult {
        due_by,
        ..JobResult::of(Ran::Done)
    })
}
