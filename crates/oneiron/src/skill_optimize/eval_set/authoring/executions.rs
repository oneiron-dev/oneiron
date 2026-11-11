//! `vault.evals.authoring.execute` (LEARNING-06, ND-130): one eval-authoring
//! pass run now, on the host that was asked, with its report kept. The
//! caller's standing (the vault owner, or an agent whose live owner Grant
//! lists the verb) is checked once, in the writer that queues the Coach's
//! eval-authoring job, or joins the one queued, and admits that very job.
//! The pass's effects stay the Coach's acts, as at night: the same stamp,
//! lease, budget line and skill provenance (LEARN-EXEC-SHAPE = A). The kept
//! record names the caller and the attempt; only an attempt this door
//! admitted takes one, and its first end stands.

use serde::{Deserialize, Serialize};

use super::{EvalAuthoringInventory, EvalAuthoringPlan, EvalAuthoringReport};
use crate::EdgeActorClass;
use crate::Vault;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::claim::maintenance_kind::{COACH_EVAL_AUTHORING_FACET, COACH_HOST_QUEUE_KIND};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::invalid;

/// The verb a Grant lists to name the request: the row's own name.
pub const EVAL_AUTHORING_EXECUTE_VERB: &str = "vault.evals.authoring.execute";

/// One requested pass's record, by its Coach attempt's id.
const EXECUTIONS: SideTable<EntityId, EvalAuthoringExecution, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_EVAL_AUTHORING_EXECUTION);

/// Why an agent with no conferring Grant is refused.
const NO_GRANT: &str = "no live Grant from a live owner names this agent and lists the verb";

/// `vault.evals.authoring.execute`'s input: none. The pass reads the whole
/// inventory, as the nightly pass does; the caller supplies no plan, skill,
/// lease or target.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringExecuteRequest {}

/// Who asked for a pass, as its admission checked them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalAuthoringCaller {
    /// The vault owner, on its own proof.
    Owner { person: EntityId },
    /// An agent, on the live owner Grant that listed the verb.
    Agent { agent: EntityId, grant: EntityId },
}

/// What one requested pass came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalAuthoringOutcome {
    /// Admitted and not ended: running, or its host stopped first.
    Running,
    /// The inventory held nothing new to decide: no model call.
    NoWork,
    /// No Coach seat, no loadable approved skill, or no seat took the call.
    Unavailable,
    /// The model's answer held no plan.
    NoPlan,
    /// The engine refused the plan; nothing applied.
    Refused,
    /// The plan applied; the report says what each step did.
    Applied,
    /// The pass ended in an error, and its attempt failed with it.
    Failed,
}

/// The eval-authoring skill revision a pass loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringSkillRun {
    pub skill: EntityId,
    pub revision: String,
}

/// One requested pass's kept record, by its Coach attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringExecution {
    pub attempt: EntityId,
    pub caller: EvalAuthoringCaller,
    pub requested_at: u64,
    pub outcome: EvalAuthoringOutcome,
    pub ended_at: Option<u64>,
    pub skill: Option<EvalAuthoringSkillRun>,
    /// The inventory the plan was made from, once the pass read one.
    pub inventory_digest: Option<String>,
    /// What the plan did; only an applied pass has one.
    pub report: Option<EvalAuthoringReport>,
}

/// `vault.evals.authoring.execute`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalAuthoringExecuteAnswer {
    /// The request's own pass ran on this host; its kept record.
    Ran {
        execution: Box<EvalAuthoringExecution>,
    },
    /// The queue's eval-authoring job was not ready for this host, so no
    /// pass ran for this request; `vault.evals.authoring.result` reads the
    /// job's state.
    Waiting { attempt: EntityId },
}

/// What a request admitted.
#[derive(Debug)]
pub enum EvalAuthoringAdmission {
    /// The request's own Coach attempt, leased to the host that asked, and
    /// the record that names its caller.
    Admitted {
        attempt: Box<DreamerAdmittedAttempt>,
        execution: Box<EvalAuthoringExecution>,
    },
    /// The queue's eval-authoring job is not ready for this host now:
    /// another pass holds its lease, or its budget line is spent. Nothing
    /// runs for this request; the queue reports the job's state.
    Waiting { attempt: EntityId },
}

/// Admits `memory`'s caller for [`EVAL_AUTHORING_EXECUTE_VERB`] and, in the
/// same writer, queues the Coach's eval-authoring job (coalescing with the
/// one queued, as `vault.evals.author_now` does) and admits that very job on
/// `admit`'s lease and budget line. An admitted request's record is written
/// in that writer, naming the caller.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the live vault owner nor an agent
/// with a live owner Grant listing the verb; storage and queue errors.
pub fn admit_eval_authoring_execution(
    memory: &Memory<'_>,
    _input: EvalAuthoringExecuteRequest,
    admit: AdmitDreamerAttempt,
) -> MemoryResult<EvalAuthoringAdmission> {
    let vault = memory.vault();
    let store = DreamerRunnerStore::new(vault);
    let requested_at = admit.now;
    let admission = vault.try_with_write_txn_grouped(|txn| -> MemoryResult<_> {
        let caller = admit_caller_in_txn(memory, txn)?;
        let queued = match store.enqueue_kind_in_txn(
            txn,
            COACH_HOST_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_EVAL_AUTHORING_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_EVAL_AUTHORING_FACET.into()),
            None,
            requested_at,
        )? {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        let id = queued.attempt.id;
        let attempt = EntityId::from_bytes(*id.as_bytes())?;
        match store.admit_requested_attempt_in_txn(txn, COACH_HOST_QUEUE_KIND, id, admit)? {
            DreamerAdmissionOutcome::Admitted(admitted) => {
                let execution = EvalAuthoringExecution {
                    attempt,
                    caller,
                    requested_at,
                    outcome: EvalAuthoringOutcome::Running,
                    ended_at: None,
                    skill: None,
                    inventory_digest: None,
                    report: None,
                };
                EXECUTIONS.put(vault, txn, &attempt, &execution)?;
                Ok(EvalAuthoringAdmission::Admitted {
                    attempt: admitted,
                    execution: Box::new(execution),
                })
            }
            _ => Ok(EvalAuthoringAdmission::Waiting { attempt }),
        }
    })?;
    vault.store.notify_attempt_observers();
    Ok(admission)
}

/// [`admit_eval_authoring_execution`]'s caller check alone, in a read
/// snapshot: a host door's early refusal. The admitting writer checks again.
///
/// # Errors
///
/// The writer's FORBIDDEN refusals; storage errors.
pub fn eval_authoring_execute_admits(memory: &Memory<'_>) -> MemoryResult<()> {
    let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
    admit_caller_in_txn(memory, &txn).map(drop)
}

/// The kept record of the requested pass `attempt`; `None` for an attempt
/// no request admitted.
///
/// # Errors
///
/// Storage errors; a record that does not decode.
pub fn eval_authoring_execution(
    vault: &Vault,
    attempt: &EntityId,
) -> Result<Option<EvalAuthoringExecution>> {
    let txn = vault.store.env.read_txn()?;
    EXECUTIONS.get(vault, &txn, attempt)
}

impl Vault {
    /// Applies the Coach's `plan` on a requested pass, as
    /// [`Self::run_coach_eval_authoring`] does at night, and ends the pass's
    /// record with what it did: `Applied` with its report, or `Refused` for
    /// a plan the engine refused, which applied nothing.
    ///
    /// # Errors
    ///
    /// An attempt that is not a requested eval-authoring Coach attempt;
    /// storage errors, which leave the record running.
    pub fn apply_requested_eval_authoring(
        &self,
        attempt: &DreamerAdmittedAttempt,
        plan: EvalAuthoringPlan,
        inventory: &EvalAuthoringInventory,
        skill: (EntityId, String),
        now: u64,
    ) -> Result<EvalAuthoringExecution> {
        self.requested_execution(attempt)?;
        let ran = EvalAuthoringSkillRun {
            skill: skill.0,
            revision: skill.1.clone(),
        };
        let digest = inventory.inventory_digest.clone();
        let (outcome, report) =
            match self.run_coach_eval_authoring(attempt, plan, inventory, skill, now) {
                Ok(report) => (EvalAuthoringOutcome::Applied, Some(report)),
                Err(Error::Artifact(_)) => (EvalAuthoringOutcome::Refused, None),
                Err(error) => return Err(error),
            };
        self.end_execution(attempt, outcome, Some(ran), Some(digest), report, now)
    }

    /// Ends a requested pass that applied no plan: `NoWork`, `Unavailable`,
    /// `NoPlan` or `Failed`, with the skill and inventory it got to.
    ///
    /// # Errors
    ///
    /// Any other outcome, which only [`Self::apply_requested_eval_authoring`]
    /// records; an attempt that is not a requested eval-authoring Coach
    /// attempt; storage errors.
    pub fn end_requested_eval_authoring(
        &self,
        attempt: &DreamerAdmittedAttempt,
        outcome: EvalAuthoringOutcome,
        skill: Option<(EntityId, String)>,
        inventory_digest: Option<String>,
        now: u64,
    ) -> Result<EvalAuthoringExecution> {
        if matches!(
            outcome,
            EvalAuthoringOutcome::Running
                | EvalAuthoringOutcome::Applied
                | EvalAuthoringOutcome::Refused
        ) {
            return Err(invalid(
                "a requested eval-authoring pass ends so only when it applied no plan",
            ));
        }
        self.requested_execution(attempt)?;
        let ran = skill.map(|(skill, revision)| EvalAuthoringSkillRun { skill, revision });
        self.end_execution(attempt, outcome, ran, inventory_digest, None, now)
    }

    /// `attempt` is the eval-authoring facet's Coach attempt and a request
    /// admitted it.
    fn requested_execution(&self, attempt: &DreamerAdmittedAttempt) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_EVAL_AUTHORING_FACET)?;
        let id = EntityId::from_bytes(*attempt.status.attempt.id.as_bytes())?;
        if eval_authoring_execution(self, &id)?.is_none() {
            return Err(invalid(
                "the attempt was not requested through vault.evals.authoring.execute",
            ));
        }
        Ok(())
    }

    /// Writes the end of `attempt`'s record, in one writer; a record that
    /// already ended keeps its first end.
    fn end_execution(
        &self,
        attempt: &DreamerAdmittedAttempt,
        outcome: EvalAuthoringOutcome,
        skill: Option<EvalAuthoringSkillRun>,
        inventory_digest: Option<String>,
        report: Option<EvalAuthoringReport>,
        now: u64,
    ) -> Result<EvalAuthoringExecution> {
        let id = EntityId::from_bytes(*attempt.status.attempt.id.as_bytes())?;
        self.with_write_txn_grouped(|txn| {
            let mut execution = EXECUTIONS.get(self, txn, &id)?.ok_or_else(|| {
                invalid("the attempt was not requested through vault.evals.authoring.execute")
            })?;
            if execution.outcome != EvalAuthoringOutcome::Running {
                return Ok(execution);
            }
            execution.outcome = outcome;
            execution.ended_at = Some(now);
            execution.skill = skill;
            execution.inventory_digest = inventory_digest;
            execution.report = report;
            EXECUTIONS.put(self, txn, &id, &execution)?;
            Ok(execution)
        })
    }
}

/// The caller an admitted request runs for, in `txn`: the vault owner while
/// a live person, or an agent on the live owner Grant that lists
/// [`EVAL_AUTHORING_EXECUTE_VERB`]. The caller's actor binding and any
/// credential it presented are checked first.
fn admit_caller_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<EvalAuthoringCaller> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        if !crate::consent::person_is_live_in_txn(vault, txn, &memory.actor())? {
            return Err(refused("the vault owner is not a live person"));
        }
        return Ok(EvalAuthoringCaller::Owner {
            person: memory.actor(),
        });
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        EVAL_AUTHORING_EXECUTE_VERB,
    )? {
        Ok(standing) => Ok(EvalAuthoringCaller::Agent {
            agent: memory.actor(),
            grant: standing.grant.ok_or_else(|| refused(NO_GRANT))?,
        }),
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => Err(refused(NO_GRANT)),
    }
}

/// The verb's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{EVAL_AUTHORING_EXECUTE_VERB} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
