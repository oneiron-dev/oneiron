//! The creator a created TASK's realizing agent runs under (OF-532).
//!
//! A TASK an agent creates is that agent's work: the agent that realizes it
//! runs inside its creator's lease tree and project, never as a free root.
//! The creator is the exact running attempt a host bound ([`HostBinding`]),
//! never the actor, the TASK, a project's leader, a run tag, a board or a
//! field a caller writes. A create with no bound creator stays a root.
//!
//! A gated create keeps its resolved origin beside its proposal, in an
//! engine-owned witness outside the amendable proposal value, and lands
//! under it on approval. Approval may outlive the worker's lease, so the
//! landing rechecks the stored creator and its spend scope rather than the
//! lease: a creator whose row is gone, whose project moved or whose spend
//! scope has settled refuses, rather than landing as free work.
//!
//! A root create keeps a witness too when the host stamped the conversation
//! whose request started it (OF-221, [`Memory::with_origin_conversation`]):
//! no creator, only that conversation, so an approval or a wave cut that
//! lands after the chat has moved on still links the work back to it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{
    AgentDispatchInput, AgentDispatcher, SpendState, TeamRunStamp, agent_dispatch_actor,
    dispatch_origin_conversation, record_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;

use super::highway::{forbidden, invalid_state};
use super::highway_types::HostBinding;

/// Domain of the witness key a wave planning attempt derives.
const WAVE_PLAN_ORIGIN_DOMAIN: &[u8] = b"oneiron.tasks.create_origin.wave_plan.v1";

/// Proposal claim, or the id a wave planning attempt derives → the creator
/// its TASKs land under.
const ORIGINS: SideTable<[u8; 16], TaskCreateOrigin, Named> =
    SideTable::new(&side_table::TASK_CREATE_ORIGIN);

/// The creator one TASK create runs under: the creator's attempt, the
/// project its frozen dispatch input holds, its queue run tag, the
/// conversation its work started from and the team run it works in. Built
/// only from a verified host binding, or, for a root, from the host's
/// conversation stamp alone; no caller writes any field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskCreateOrigin {
    /// `None`: a root create the host stamped with its conversation.
    parent_attempt: Option<AttemptId>,
    project_ref: Option<EntityId>,
    run_id: Option<String>,
    /// OF-221: the conversation whose request started the work: the host's
    /// stamp for a root, the creator's stored origin for a child.
    origin_conversation: Option<EntityId>,
    /// OF-540: the team run the creator's dispatch froze; `None` is no team.
    team: Option<TeamRunStamp>,
}

impl TaskCreateOrigin {
    pub(super) const fn parent_attempt(&self) -> Option<AttemptId> {
        self.parent_attempt
    }

    pub(super) const fn origin_conversation(&self) -> Option<EntityId> {
        self.origin_conversation
    }

    pub(super) const fn team(&self) -> Option<&TeamRunStamp> {
        self.team.as_ref()
    }

    pub(super) const fn project_ref(&self) -> Option<EntityId> {
        self.project_ref
    }

    pub(super) fn run_id(&self) -> Option<String> {
        self.run_id.clone()
    }
}

fn creator_gone() -> crate::memory::MemoryError {
    invalid_state(
        "the task's creator attempt is no longer a live agent run",
        "Create the task again from a running agent, or as a root from the owner.",
    )
}

/// The creator's row and frozen dispatch input, read in `txn`. Only an
/// agent dispatch run creates under a lease tree.
fn creator_run_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> MemoryResult<(AttemptRecord, AgentDispatchInput)> {
    let record = AttemptQueue::new(vault)
        .get_in_txn(txn, attempt)?
        .ok_or_else(creator_gone)?;
    let input = record_dispatch_input(&record).ok_or_else(creator_gone)?;
    Ok((record, input))
}

/// The creating surface's actor must be the agent the creator run is.
fn require_creator_actor(memory: &Memory<'_>, input: &AgentDispatchInput) -> MemoryResult<()> {
    if agent_dispatch_actor(input)? != WriteActor::new(memory.actor(), memory.actor_class()) {
        return Err(forbidden(
            "a bound task create runs as its creator agent",
            "Create the task from the agent run the host bound.",
        ));
    }
    Ok(())
}

/// Resolves the origin a create runs under, in the create's own
/// transaction. A live host binding's: the bound attempt must still be
/// leased by the binding's owner at its generation, be an agent dispatch,
/// and be run by this surface's actor; a lost lease refuses, it never falls
/// back to a root. With no binding the create is a root, witnessed only when
/// the host stamped its conversation; `None` otherwise.
pub(crate) fn task_create_origin_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    binding: Option<&HostBinding>,
) -> MemoryResult<Option<TaskCreateOrigin>> {
    let Some(binding) = binding else {
        return Ok(memory
            .origin_conversation()
            .map(|conversation| TaskCreateOrigin {
                parent_attempt: None,
                project_ref: None,
                run_id: None,
                origin_conversation: Some(conversation),
                team: None,
            }));
    };
    let (record, input) = creator_run_in(memory.vault(), txn, binding.parent())?;
    if !record.state.is_running()
        || record.lease_owner.as_deref() != Some(binding.lease_owner())
        || record.attempt_count != binding.attempt_count()
    {
        return Err(invalid_state(
            "the creator's lease is no longer current",
            "Create the task while the agent's try is leased.",
        ));
    }
    require_creator_actor(memory, &input)?;
    let origin_conversation =
        crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
            .ok()
            .and_then(|payload| dispatch_origin_conversation(&payload));
    let origin = TaskCreateOrigin {
        parent_attempt: Some(record.id),
        project_ref: input.project_ref,
        run_id: record.run_id.clone(),
        origin_conversation,
        team: input.team,
    };
    require_creator_in_txn(memory, txn, &origin)?;
    Ok(Some(origin))
}

/// Rechecks an origin where its agent launches, live or stored: the creator
/// row is still an agent dispatch run by this surface's actor, in the
/// project the origin recorded, and its spend scope, when it has one, is
/// still open. Dispatch then admits the launch under that scope. A root
/// witness names no creator, so there is nothing to recheck.
pub(super) fn require_creator_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    origin: &TaskCreateOrigin,
) -> MemoryResult<()> {
    let Some(parent) = origin.parent_attempt else {
        return Ok(());
    };
    let (_, input) = creator_run_in(memory.vault(), txn, parent)?;
    require_creator_actor(memory, &input)?;
    if input.project_ref != origin.project_ref {
        return Err(creator_gone());
    }
    let scope = AgentDispatcher::new(memory.vault()).attempt_spend_scope_in_txn(txn, parent)?;
    if scope.is_some_and(|scope| scope.state != SpendState::Open) {
        return Err(invalid_state(
            "the creator's spend lease has settled",
            "Create the task again from a running agent, or as a root from the owner.",
        ));
    }
    Ok(())
}

/// Witnesses the origin a proposal's approved TASK lands under, in the
/// proposal's transaction.
pub(super) fn put_proposal_origin_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal_ref: EntityId,
    origin: &TaskCreateOrigin,
) -> MemoryResult<()> {
    ORIGINS.put(&vault.store, wtxn, proposal_ref.as_bytes(), origin)?;
    Ok(())
}

/// The origin a proposal was parked under; `None`: a root create.
pub(super) fn proposal_origin_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal_ref: EntityId,
) -> MemoryResult<Option<TaskCreateOrigin>> {
    Ok(ORIGINS.get(&vault.store, txn, proposal_ref.as_bytes())?)
}

fn wave_plan_key(attempt: AttemptId) -> MemoryResult<[u8; 16]> {
    Ok(*EntityId::derive(WAVE_PLAN_ORIGIN_DOMAIN, &[attempt.as_bytes()])?.as_bytes())
}

/// Witnesses the creator a wave planning attempt's cut lands under, in the
/// enqueue's transaction.
pub(super) fn put_wave_plan_origin_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    origin: &TaskCreateOrigin,
) -> MemoryResult<()> {
    ORIGINS.put(&vault.store, wtxn, &wave_plan_key(attempt)?, origin)?;
    Ok(())
}

/// The creator a wave planning attempt was queued under; `None`: a
/// host-created plan, whose TASKs stay roots.
pub(super) fn wave_plan_origin_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> MemoryResult<Option<TaskCreateOrigin>> {
    Ok(ORIGINS.get(&vault.store, txn, &wave_plan_key(attempt)?)?)
}
