//! The Schedule primitive's verbs (DESIGN 15-setting-primitive, stage 0.2):
//! `vault.schedules.list`, `.arm`, `.disarm` and `.run`.
//!
//! The caller is the vault owner, on the owner's own proof, or an agent on its verified binding.
//! Changing a cadence is a choice, a Setting's; these verbs arm, disarm and hurry the armed
//! jobs the job kinds let an actor arm.

use serde::{Deserialize, Serialize};

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult,
};
use crate::schedule::{ScheduleCaller, ScheduleView, Trigger};

const LIST: &str = "vault.schedules.list";
const ARM: &str = "vault.schedules.arm";
const DISARM: &str = "vault.schedules.disarm";
const RUN: &str = "vault.schedules.run";

/// `vault.schedules.list` input: what to narrow the armed jobs to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleListRequest {
    /// One job kind's code.
    #[serde(default)]
    pub job: Option<String>,
    /// One subject, 32 hex.
    #[serde(default)]
    pub subject: Option<String>,
}

/// What `vault.schedules.list` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScheduleList {
    /// The armed jobs the caller may see, in job and subject order.
    pub schedules: Vec<ScheduleView>,
}

/// `vault.schedules.arm` input: one job to arm, or arm again.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleArmRequest {
    /// The job kind's code.
    pub job: String,
    /// What the job is about, 32 hex; none for a job about nothing.
    #[serde(default)]
    pub subject: Option<String>,
    /// When it fires.
    pub trigger: Trigger,
}

/// `vault.schedules.disarm` and `vault.schedules.run` input: one armed job.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRef {
    /// The job kind's code.
    pub job: String,
    /// What the job is about, 32 hex.
    #[serde(default)]
    pub subject: Option<String>,
}

/// What `vault.schedules.disarm` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScheduleDisarmed {
    /// Whether an armed job went; false when none was armed.
    pub disarmed: bool,
}

fn subject_of(subject: Option<&str>) -> MemoryResult<Option<EntityId>> {
    subject.map(EntityId::from_hex).transpose().map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "a subject is 32 hex".to_owned(),
            &[],
        )
    })
}

/// The caller behind `memory`, run through `act`: the owner when its proof holds, else its
/// verified agent.
fn as_caller<T>(
    memory: &Memory<'_>,
    verb: &str,
    act: impl FnOnce(ScheduleCaller<'_>) -> crate::Result<T>,
) -> MemoryResult<T> {
    if let Ok(owner) = memory.embedded_owner(verb) {
        return Ok(act(ScheduleCaller::Owner(&owner))?);
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} takes the vault owner or an agent"),
            &["Call as the owner, or as an agent the owner granted."],
        ));
    }
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    crate::memory::verify_actor_binding_in_txn(vault, &txn, memory.actor(), memory.actor_class())?;
    drop(txn);
    Ok(act(ScheduleCaller::Agent(memory.actor()))?)
}

/// `vault.schedules.list`: the armed jobs the caller may see.
///
/// # Errors
///
/// BAD_REQUEST for a subject that is not 32 hex; FORBIDDEN for a caller that is neither the
/// owner nor an agent; storage errors.
pub fn schedule_list_embedded(
    memory: &Memory<'_>,
    input: ScheduleListRequest,
) -> MemoryResult<ScheduleList> {
    let subject = subject_of(input.subject.as_deref())?;
    as_caller(memory, LIST, |caller| {
        memory
            .vault()
            .schedules_for(caller, input.job.as_deref(), subject)
            .map(|schedules| ScheduleList { schedules })
    })
}

/// `vault.schedules.arm`: arms a job whose kind lets an actor arm it, under the caller's own
/// power.
///
/// # Errors
///
/// BAD_REQUEST for an unknown job, a trigger that can never fire, or a caller without the power;
/// FORBIDDEN for a caller that is neither the owner nor an agent; storage errors.
pub fn schedule_arm_embedded(
    memory: &Memory<'_>,
    input: ScheduleArmRequest,
) -> MemoryResult<ScheduleView> {
    let subject = subject_of(input.subject.as_deref())?;
    as_caller(memory, ARM, |caller| {
        memory
            .vault()
            .arm_schedule(Some(caller), &input.job, subject, input.trigger)
    })
}

/// `vault.schedules.disarm`: disarms a job the caller armed, or, for the owner or a class
/// holder, any job of the kind.
///
/// # Errors
///
/// As [`schedule_arm_embedded`].
pub fn schedule_disarm_embedded(
    memory: &Memory<'_>,
    input: ScheduleRef,
) -> MemoryResult<ScheduleDisarmed> {
    let subject = subject_of(input.subject.as_deref())?;
    as_caller(memory, DISARM, |caller| {
        memory
            .vault()
            .disarm_schedule(Some(caller), &input.job, subject)
            .map(|disarmed| ScheduleDisarmed { disarmed })
    })
}

/// `vault.schedules.run`: "run now": the armed job is due from now until a run starts.
///
/// # Errors
///
/// As [`schedule_arm_embedded`]; a job that is not armed.
pub fn schedule_run_embedded(
    memory: &Memory<'_>,
    input: ScheduleRef,
) -> MemoryResult<ScheduleView> {
    let subject = subject_of(input.subject.as_deref())?;
    as_caller(memory, RUN, |caller| {
        memory
            .vault()
            .request_schedule_run(caller, &input.job, subject)
    })
}
