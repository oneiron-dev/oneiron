//! `vault.evals.authoring.execute` (LEARNING-06, ND-130): one eval-authoring
//! pass run now, on the host that was asked, with its report kept. The
//! caller's standing (the vault owner, or an agent whose live owner Grant
//! lists the verb) is checked once, in the writer that queues the Coach's
//! eval-authoring job, or joins the one queued, and admits that very job.
//! The pass's effects stay the Coach's acts, as at night: the same stamp,
//! lease, budget line and skill provenance (LEARN-EXEC-SHAPE = A). The kept
//! record names the caller and the attempt; only an attempt this door
//! admitted takes one, and its first end stands. A plan's effects run under
//! a claim on that record, so no effect runs once it has ended. An attempt
//! leased again after its lease lapsed keeps its first request's record: it
//! runs on that record while it is running, and runs no second pass once it
//! has ended. Each writer that claims, ends or recovers a record first checks
//! that the attempt's lease is still the one its host was admitted on: a host
//! whose lease lapsed, and whose attempt another host leased again, changes
//! no record.

use serde::{Deserialize, Serialize};

use super::{EvalAuthoringInventory, EvalAuthoringPlan, EvalAuthoringReport};
use crate::EdgeActorClass;
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
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

#[doc(hidden)]
pub use oneiron_verb_wire::skill_optimize::eval_set::authoring::executions::{
    EvalAuthoringCaller, EvalAuthoringExecuteAnswer, EvalAuthoringExecuteRequest,
    EvalAuthoringExecution, EvalAuthoringOutcome, EvalAuthoringSkillRun,
};

/// What a request admitted.
#[derive(Debug)]
pub enum EvalAuthoringAdmission {
    /// The request's own Coach attempt, leased to the host that asked, and
    /// the record that names its caller: this request's, or the running
    /// record of the request that first admitted the attempt.
    Admitted {
        attempt: Box<DreamerAdmittedAttempt>,
        execution: Box<EvalAuthoringExecution>,
    },
    /// The attempt an earlier request admitted, leased again after its pass
    /// ended and before its host settled the lease. No pass runs again: the
    /// host settles the lease by the kept end.
    Ended {
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
/// in that writer, naming the caller; an attempt an earlier request admitted
/// keeps that request's record.
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
                if let Some(kept) = recover_in_txn(vault, txn, &attempt, requested_at)? {
                    let execution = Box::new(kept);
                    return Ok(if execution.outcome == EvalAuthoringOutcome::Running {
                        EvalAuthoringAdmission::Admitted {
                            attempt: admitted,
                            execution,
                        }
                    } else {
                        EvalAuthoringAdmission::Ended {
                            attempt: admitted,
                            execution,
                        }
                    });
                }
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
    /// record with what it did: `Applied` with its report, `Refused` for a
    /// plan the engine refused, which applied nothing, or `Failed` for an
    /// error once the effects began. The effects run under a claim on the
    /// record, taken under the attempt's live lease: a record that is not
    /// running (it ended, or another apply holds it) is answered as it
    /// stands, and no effect runs.
    ///
    /// # Errors
    ///
    /// An attempt that is not a requested eval-authoring Coach attempt, or
    /// whose lease its host no longer holds; storage errors; an error from
    /// the plan's effects, after the record ended `Failed`.
    pub fn apply_requested_eval_authoring(
        &self,
        attempt: &DreamerAdmittedAttempt,
        plan: EvalAuthoringPlan,
        inventory: &EvalAuthoringInventory,
        skill: (EntityId, String),
        now: u64,
    ) -> Result<EvalAuthoringExecution> {
        let id = self.requested_execution(attempt)?;
        if let Some(kept) = self.claim_execution(attempt, &id)? {
            return Ok(kept);
        }
        let ran = Some(EvalAuthoringSkillRun {
            skill: skill.0,
            revision: skill.1.clone(),
        });
        let inventory_digest = Some(inventory.inventory_digest.clone());
        let (outcome, report, error) =
            match self.run_coach_eval_authoring(attempt, plan, inventory, skill, now) {
                Ok(report) => (EvalAuthoringOutcome::Applied, Some(report), None),
                Err(Error::Artifact(_)) => (EvalAuthoringOutcome::Refused, None, None),
                // The claim admits no other end, so the record ends here.
                Err(error) => (EvalAuthoringOutcome::Failed, None, Some(error)),
            };
        let end = ExecutionEnd {
            outcome,
            skill: ran,
            inventory_digest,
            report,
        };
        let ended = self.end_execution(attempt, &id, &[EvalAuthoringOutcome::Applying], end, now);
        let Some(error) = error else {
            return ended;
        };
        if let Err(record) = ended {
            tracing::warn!(%record, "a requested eval-authoring pass could not record its failure");
        }
        Err(error)
    }

    /// Ends a requested pass that applied no plan: `NoWork`, `Unavailable`,
    /// `NoPlan` or `Failed`, with the skill and inventory it got to. Only a
    /// running record ends so, and a `Failed` end also ends the claim this
    /// host's apply holds, whose own end did not record; any other record
    /// answers as it stands.
    ///
    /// # Errors
    ///
    /// Any other outcome, which only [`Self::apply_requested_eval_authoring`]
    /// records; an attempt that is not a requested eval-authoring Coach
    /// attempt, or whose lease its host no longer holds; storage errors.
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
                | EvalAuthoringOutcome::Applying
                | EvalAuthoringOutcome::Applied
                | EvalAuthoringOutcome::Refused
        ) {
            return Err(invalid(
                "a requested eval-authoring pass ends so only when it applied no plan",
            ));
        }
        let id = self.requested_execution(attempt)?;
        let end = ExecutionEnd {
            outcome,
            skill: skill.map(|(skill, revision)| EvalAuthoringSkillRun { skill, revision }),
            inventory_digest,
            report: None,
        };
        // A claim is only ever this host's own: the lease fences every claim.
        let from: &[EvalAuthoringOutcome] = if outcome == EvalAuthoringOutcome::Failed {
            &[
                EvalAuthoringOutcome::Running,
                EvalAuthoringOutcome::Applying,
            ]
        } else {
            &[EvalAuthoringOutcome::Running]
        };
        self.end_execution(attempt, &id, from, end, now)
    }

    /// The kept record of a requested pass that a worker's ordinary
    /// admission leased again, after its lease lapsed; `None` for an attempt
    /// no request admitted. A record whose host stopped while its plan
    /// applied ends `Failed` here.
    ///
    /// # Errors
    ///
    /// An attempt that is not the eval-authoring facet's Coach attempt, or
    /// whose lease its host no longer holds; storage errors.
    pub fn recover_requested_eval_authoring(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<Option<EvalAuthoringExecution>> {
        self.require_coach_attempt(attempt, COACH_EVAL_AUTHORING_FACET)?;
        let id = EntityId::from_bytes(*attempt.status.attempt.id.as_bytes())?;
        self.with_write_txn_grouped(|txn| {
            require_live_lease_in_txn(self, txn, attempt)?;
            recover_in_txn(self, txn, &id, now)
        })
    }

    /// `attempt` is the eval-authoring facet's Coach attempt and a request
    /// admitted it: its record's id.
    fn requested_execution(&self, attempt: &DreamerAdmittedAttempt) -> Result<EntityId> {
        self.require_coach_attempt(attempt, COACH_EVAL_AUTHORING_FACET)?;
        let id = EntityId::from_bytes(*attempt.status.attempt.id.as_bytes())?;
        if eval_authoring_execution(self, &id)?.is_none() {
            return Err(not_requested());
        }
        Ok(id)
    }

    /// Moves `id`'s record from `Running` to `Applying`, in one writer under
    /// `attempt`'s live lease: `None` when this call took the claim, else the
    /// record as it stands.
    fn claim_execution(
        &self,
        attempt: &DreamerAdmittedAttempt,
        id: &EntityId,
    ) -> Result<Option<EvalAuthoringExecution>> {
        self.with_write_txn_grouped(|txn| {
            require_live_lease_in_txn(self, txn, attempt)?;
            let mut execution = EXECUTIONS.get(self, txn, id)?.ok_or_else(not_requested)?;
            if execution.outcome != EvalAuthoringOutcome::Running {
                return Ok(Some(execution));
            }
            execution.outcome = EvalAuthoringOutcome::Applying;
            EXECUTIONS.put(self, txn, id, &execution)?;
            Ok(None)
        })
    }

    /// Ends `id`'s record with `end` when it stands at one of `from`, in one
    /// writer under `attempt`'s live lease; a record at any other state keeps
    /// it, so its first end stands.
    fn end_execution(
        &self,
        attempt: &DreamerAdmittedAttempt,
        id: &EntityId,
        from: &[EvalAuthoringOutcome],
        end: ExecutionEnd,
        now: u64,
    ) -> Result<EvalAuthoringExecution> {
        self.with_write_txn_grouped(|txn| {
            require_live_lease_in_txn(self, txn, attempt)?;
            let mut execution = EXECUTIONS.get(self, txn, id)?.ok_or_else(not_requested)?;
            if !from.contains(&execution.outcome) {
                return Ok(execution);
            }
            execution.outcome = end.outcome;
            execution.ended_at = Some(now);
            execution.skill = end.skill;
            execution.inventory_digest = end.inventory_digest;
            execution.report = end.report;
            EXECUTIONS.put(self, txn, id, &execution)?;
            Ok(execution)
        })
    }
}

/// What a requested pass's end writes on its record.
struct ExecutionEnd {
    outcome: EvalAuthoringOutcome,
    skill: Option<EvalAuthoringSkillRun>,
    inventory_digest: Option<String>,
    report: Option<EvalAuthoringReport>,
}

/// `attempt`'s kept record in `txn`, for a worker that leased the attempt
/// again; `None` for an attempt no request admitted. A record whose host
/// stopped while its plan applied ends `Failed` at `now`: what its effects
/// did is not known.
fn recover_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &EntityId,
    now: u64,
) -> Result<Option<EvalAuthoringExecution>> {
    let Some(mut execution) = EXECUTIONS.get(vault, txn, attempt)? else {
        return Ok(None);
    };
    if execution.outcome == EvalAuthoringOutcome::Applying {
        execution.outcome = EvalAuthoringOutcome::Failed;
        execution.ended_at = Some(now);
        EXECUTIONS.put(vault, txn, attempt, &execution)?;
    }
    Ok(Some(execution))
}

/// Refuses `attempt` in `txn` unless its lease is still the one its host
/// was admitted on: a host whose lease lapsed, and whose attempt another host
/// leased again, neither claims, ends nor recovers its record.
fn require_live_lease_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
) -> Result<()> {
    let leased = &attempt.status.attempt;
    let owner = leased.lease_owner.as_deref().ok_or(invalid(
        "an admitted eval-authoring attempt names its lease owner",
    ))?;
    AttemptQueue::new(vault).require_skill_load_lease_in_txn(
        txn,
        leased.id,
        owner,
        leased.attempt_count,
    )
}

/// The refusal of an attempt no request admitted.
fn not_requested() -> Error {
    invalid("the attempt was not requested through vault.evals.authoring.execute")
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
