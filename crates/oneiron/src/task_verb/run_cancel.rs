//! Run-tree cancel of one branch through a caller-bound door (FIX 8219,
//! ARCH-0067: cancel covers own tasks and own spawns, others' are
//! proposals; Engine 10-22).
//!
//! The vault owner cancels any branch at once, by the same owner standing
//! he pauses one by. So does the owner of the TASK the
//! branch realizes, the agent whose run it is, and the agent that spawned
//! it. Every other caller's cancel becomes a proposal: the soft cancel's own
//! Proposed `tasks.cancel` claim naming the branch, and the branch is not
//! touched. Standing is judged in the writer that would cancel, so it is
//! judged as it stands when the cancel commits. A caller with no actor to
//! own a proposal keeps today's immediate cancel.

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, InterveneAttempt,
    InterveneOutcome,
};
use crate::authority::TaskActorVerb;
use crate::claim::ScopedReadActorKey;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
    facade_provenance, verify_actor_binding,
};
use crate::task_verb::sdk::AgentVerb;

use super::consts::TASK_CANCEL_PROPOSAL_PREDICATE;
use super::presence_scan::attempt_hex;
use super::rate_limit::task_verb_contract;
use super::route_receipts::DEFAULT_TASK_CANCEL_MODE;

/// What a caller with no standing over a branch should do instead.
const RUN_CANCEL_FIX: &str =
    "Cancel a branch of a TASK you own, or a run you spawned; the vault owner stops any branch.";

/// What a run-tree cancel came to.
#[derive(Debug, Clone)]
pub enum RunCancelOutcome {
    /// The caller stands to stop the branch: the queue's own outcome.
    Applied(InterveneOutcome),
    /// The caller does not: its cancel is this Proposed `tasks.cancel`
    /// claim, and the branch is untouched.
    Proposed { proposal_ref: EntityId },
}

impl Memory<'_> {
    /// Cancels the branch `input` names for this surface's caller (module
    /// docs): at once, as the queue cancels it, for a caller that stands
    /// over it in the writer that cancels; else as a proposal. The event
    /// names `input.actor`, as the run tree's cancel always named it. An
    /// actor whose binding the store refuses owns no proposal, so its cancel
    /// stays immediate (FIX 8219: no actor to own a proposal).
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a branch no row names; the queue's refusal of the
    /// transition; a proposal the claim door refuses; storage errors.
    pub fn cancel_run_branch(&self, input: InterveneAttempt) -> MemoryResult<RunCancelOutcome> {
        let input = InterveneAttempt {
            kind: AttemptInterventionKind::Cancel,
            ..input
        };
        let branch = input.id;
        let queue = AttemptQueue::new(self.vault());
        if let Err(error) = verify_actor_binding(self.vault(), self.actor(), self.actor_class()) {
            if error.code != MEMORY_CODE_FORBIDDEN {
                return Err(error);
            }
            // FIX 8219: no actor to own a proposal, so today's immediate cancel.
            return Ok(RunCancelOutcome::Applied(queue.intervene(input)?));
        }
        // Built before the writer, so its snapshot never nests in it. A
        // credential that grants no read has no key.
        let key = self.read_key().ok();
        let decided = self.vault().try_with_write_txn_grouped(|wtxn| {
            let record = queue
                .get_in_write_txn(wtxn, branch)?
                .ok_or(Error::EntityNotFound)?;
            if !self.cancel_standing_in(wtxn, key.as_ref(), &queue, &record)? {
                return Ok::<_, MemoryError>(Err(proposal_subject(&record, self.actor())));
            }
            Ok(Ok(queue.intervene_in_txn(wtxn, input)?))
        })?;
        let subject = match decided {
            Ok(outcome) => {
                self.vault().store.notify_attempt_observers();
                return Ok(RunCancelOutcome::Applied(outcome));
            }
            Err(subject) => subject,
        };
        // The soft cancel's own proposal for a target its caller does not
        // own: the claim names the branch, and nothing else is written.
        let verb = task_verb_contract(AgentVerb::Cancel);
        let (proposal_ref, _gate_decision_ref) = self.persist_task_proposal(
            TASK_CANCEL_PROPOSAL_PREDICATE,
            Value::Map(vec![
                (Value::from("target_ref"), Value::from(attempt_hex(branch))),
                (
                    Value::from("mode"),
                    Value::from(DEFAULT_TASK_CANCEL_MODE.as_str()),
                ),
            ]),
            subject,
            self.vault().store.clock.now_recorded_at(),
            facade_provenance(verb),
        )?;
        Ok(RunCancelOutcome::Proposed { proposal_ref })
    }

    /// Whether this surface's caller stands over `record` in `txn`: the
    /// vault owner; the owner of the TASK it realizes; the agent whose run
    /// it is; or the agent that spawned it.
    fn cancel_standing_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: Option<&ScopedReadActorKey>,
        queue: &AttemptQueue<'_>,
        record: &AttemptRecord,
    ) -> MemoryResult<bool> {
        if self.vault_owner_standing_in(txn, key)? {
            return Ok(true);
        }
        if let Some(task) = record
            .task_ref
            .as_deref()
            .and_then(|task| EntityId::from_hex(task).ok())
        {
            match self.highway_task_actor_in(txn, task, TaskActorVerb::Owner, RUN_CANCEL_FIX) {
                Ok(_) => return Ok(true),
                // Not the TASK's owner: its cancel is a proposal.
                Err(error) if no_standing(&error) => {}
                Err(error) => return Err(error),
            }
        }
        let Some((runner, parent)) = dispatch_of(record) else {
            return Ok(false);
        };
        if runner == Some(self.actor()) {
            return Ok(true);
        }
        let Some(parent) = parent else {
            return Ok(false);
        };
        let spawner = queue
            .get_in_write_txn(txn, parent)?
            .as_ref()
            .and_then(dispatch_of)
            .and_then(|(runner, _)| runner);
        Ok(spawner == Some(self.actor()))
    }
}

/// An agent dispatch row's own agent and the try that spawned it, as its
/// stored payload names them; `None` for any other row.
fn dispatch_of(record: &AttemptRecord) -> Option<(Option<EntityId>, Option<AttemptId>)> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let runner = decode_agent_dispatch_input(&payload.input)
        .ok()
        .and_then(|input| agent_dispatch_actor(&input).ok())
        .map(|actor| actor.entity_ref());
    Some((runner, payload.parent_attempt))
}

/// Whether the TASK standing check refused `error` as a caller that is not
/// the TASK's owner, rather than failing.
fn no_standing(error: &MemoryError) -> bool {
    error.code == MEMORY_CODE_FORBIDDEN || error.code == MEMORY_CODE_NOT_FOUND
}

/// The subject a proposal to cancel `record` is about: the TASK it
/// realizes, else the proposing caller, as the soft cancel's spawn
/// proposal names it.
fn proposal_subject(record: &AttemptRecord, caller: EntityId) -> EntityId {
    record
        .task_ref
        .as_deref()
        .and_then(|task| EntityId::from_hex(task).ok())
        .unwrap_or(caller)
}
