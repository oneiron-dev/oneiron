//! The owner's run doors over one TASK's branches (DOOR-100, ARCH-0026
//! `#run-tree`): `vault.tasks.cancel_force`, canon's `cancel.force`, the
//! vault owner's unrefusable stop of every live branch, and
//! `vault.runs.branches.get`, the owner's read of every branch as the queue
//! holds it.
//!
//! The force is the hard rung only. It reaches any TASK in the vault, not
//! only one its owner's actor created, and asks no gate and opens no
//! proposal: the owner's proof, rechecked in the writing transaction, is the
//! authority. The soft `cancel` and the actor-bound
//! [`Memory::cancel_force`](crate::Memory::cancel_force) keep their own rights.
//!
//! A branch reads exactly as its attempt row stores it: lifecycle state,
//! the pure [`AgentRunStatus`] projection of that state, result, typed asks
//! and signals, and the whole cancel protocol evidence (landing, resume
//! point, terminal cancellation, receipts). Nothing here invents progress,
//! a next breakpoint or a wait class.

use serde::{Deserialize, Serialize};

use super::presence_scan::{attempt_hex, superseded_attempt_ids};
use crate::agent_run_status::{AgentRunStatus, project_agent_run_status};
use crate::attempt_queue::{
    AttemptCancelState, AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState,
    ForceAttemptCancel, ForceCancelAuthority, ForceCancelOutcome, validate_signal_cancel,
};
use crate::consent::AuthenticatedOwner;
use crate::context_board::cancel_task_in_txn;
use crate::error::Error;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_TASK;
use crate::run_tree::{RunAsk, RunBranchSignal, RunTreeStatus};
use crate::{EntityId, Vault};

/// What a door that names no TASK should name instead.
const TASK_FIX: &str =
    "Name a TASK ref; a spawned agent reads by its attempt through vault.agents.spawn.get.";

/// The owner's force: every live branch of `task_ref` stops, for `reason`
/// when one is given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelForceRequest {
    pub task_ref: EntityId,
    /// Kept on each terminal cancellation receipt the force writes.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the force did: whether it stopped anything, how many branches this
/// call cancelled, and every branch of the TASK after it. A repeat on
/// settled branches stops nothing, writes nothing and reads them as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CancelForceReceipt {
    pub task_ref: EntityId,
    pub effected: bool,
    pub forced: u32,
    pub branches: Vec<RunBranchView>,
}

/// The owner's read of every branch of one TASK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunBranchesRequest {
    pub task_ref: EntityId,
}

/// Every branch of the TASK, in the order the queue created them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBranchesView {
    pub task_ref: EntityId,
    pub branches: Vec<RunBranchView>,
}

/// One branch: one attempt row realizing the TASK, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBranchView {
    /// The attempt id, as `steer` names its branch.
    pub branch: String,
    #[serde(default)]
    pub run_id: Option<String>,
    pub state: AttemptState,
    /// The projection of `state` every run-tree viewer reads. A cancelled
    /// branch reads `failed` here; its cause is `cancel_state`'s.
    pub agent_status: AgentRunStatus,
    /// The lease generation within this try.
    pub attempt_count: u32,
    /// The artifact version the branch's durable output lives in.
    #[serde(default)]
    pub result_ref: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Durable ask handles, partial answers included.
    pub asks: Vec<RunAsk>,
    /// The branch's control inbox and settled replay receipts.
    pub signals: Vec<RunBranchSignal>,
    /// Landing, resume point (the saved partial result a successor reads
    /// first), terminal cancellation and every cancel receipt.
    pub cancel_state: AttemptCancelState,
}

/// Stops, as the vault owner and unrefusably, every live branch of
/// `input.task_ref`: in one write transaction the owner is rechecked, each
/// branch no later try replaces and not yet terminal is force-cancelled on
/// the owner's grounds, and the TASK records its cancellation once one
/// really stopped. Each stopped branch's running step stops after commit.
///
/// # Errors
///
/// `NOT_FOUND` for a ref that names nothing, or a TASK no attempt realizes;
/// `BAD_REQUEST` for a ref that is not a TASK; a reason the cancel receipt
/// refuses; a stale owner proof; storage errors.
pub fn cancel_force_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CancelForceRequest,
) -> MemoryResult<CancelForceReceipt> {
    let CancelForceRequest { task_ref, reason } = input;
    let queue = AttemptQueue::new(vault);
    let now = vault.store.clock.now_recorded_at();
    let (records, stopped) = vault.try_with_write_txn_grouped(|wtxn| {
        let actor = owner.revalidate_in_txn(vault, wtxn)?;
        let authority = ForceCancelAuthority::owner(actor.to_hex().as_str())?;
        // The actor and reason checks every cancel receipt takes, before a
        // row changes: a repeat that stops nothing refuses a bad reason too.
        validate_signal_cancel(authority.actor(), reason.as_deref())?;
        let task = task_in(vault, &*wtxn, task_ref)?;
        let mut records = branches(&task, queue.list_task_in_write_txn(&*wtxn, &task)?)?;
        let superseded = superseded_attempt_ids(&records);
        let mut stopped: Vec<(AttemptId, u32)> = Vec::new();
        for record in &mut records {
            if superseded.contains(&record.id) || record.state.is_terminal() {
                continue;
            }
            let outcome = queue.force_cancel_in_txn(
                wtxn,
                ForceAttemptCancel {
                    id: record.id,
                    authority: authority.clone(),
                    reason: reason.clone(),
                    now,
                },
            )?;
            *record = match outcome {
                ForceCancelOutcome::Cancelled(after) => {
                    stopped.push((after.id, after.attempt_count));
                    after
                }
                ForceCancelOutcome::AlreadyCancelled(after)
                | ForceCancelOutcome::AlreadySettled(after) => after,
            };
        }
        // Only a force that really stopped a branch records the TASK's
        // cancellation: the fact is a stop that happened.
        if !stopped.is_empty() {
            cancel_task_in_txn(vault, wtxn, task_ref, actor, now)?;
        }
        Ok::<_, MemoryError>((records, stopped))
    })?;
    if !stopped.is_empty() {
        vault.store.notify_attempt_observers();
        // Committed: the step each stopped lease was running stops (FIX 600).
        for (id, generation) in &stopped {
            crate::engine_executor::stop_attempt_step(Some(vault), *id, *generation);
        }
    }
    Ok(CancelForceReceipt {
        task_ref,
        effected: !stopped.is_empty(),
        forced: u32::try_from(stopped.len()).unwrap_or(u32::MAX),
        branches: records.into_iter().map(branch_view).collect(),
    })
}

/// Reads, as the vault owner, every branch of `input.task_ref` in one read
/// transaction: each attempt row realizing the TASK, archived ones too, as
/// stored.
///
/// # Errors
///
/// `NOT_FOUND` for a ref that names nothing, or a TASK no attempt realizes;
/// `BAD_REQUEST` for a ref that is not a TASK; a stale owner proof; storage
/// errors.
pub fn read_branches_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RunBranchesRequest,
) -> MemoryResult<RunBranchesView> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let task = task_in(vault, &txn, input.task_ref)?;
    let records = branches(
        &task,
        AttemptQueue::new(vault).list_task_in_txn(&txn, &task)?,
    )?;
    Ok(RunBranchesView {
        task_ref: input.task_ref,
        branches: records.into_iter().map(branch_view).collect(),
    })
}

/// The hex of `task_ref`, refused unless it names a TASK.
fn task_in(vault: &Vault, txn: &heed::RoTxn<'_>, task_ref: EntityId) -> MemoryResult<String> {
    let hex = task_ref.to_hex();
    match vault.get_entity_type_in_txn(txn, &task_ref)? {
        Some(ENTITY_TYPE_TASK) => Ok(hex),
        Some(_) => Err(MemoryError::bad_request_with(
            format!("{hex} is not a TASK"),
            &[TASK_FIX],
        )),
        None => Err(MemoryError::not_found(format!(
            "no TASK {hex} is in this vault"
        ))),
    }
}

/// The TASK's attempt rows, refused when there are none: a TASK nothing has
/// run has no branch.
fn branches(task: &str, records: Vec<AttemptRecord>) -> MemoryResult<Vec<AttemptRecord>> {
    if records.is_empty() {
        return Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            format!("no attempt realizes TASK {task}: it has no branch"),
            &[
                "A TASK nothing has run yet has no branch to read or stop; cancel stops the TASK itself.",
            ],
        ));
    }
    Ok(records)
}

/// One attempt row as its branch view: every field as stored, the agent
/// status projected from the stored state alone.
fn branch_view(record: AttemptRecord) -> RunBranchView {
    RunBranchView {
        branch: attempt_hex(record.id),
        run_id: record.run_id,
        state: record.state,
        agent_status: project_agent_run_status(RunTreeStatus::from(record.state)),
        attempt_count: record.attempt_count,
        result_ref: record.result_ref.map(AttemptResultRef::into_string),
        last_error: record.last_error,
        asks: record.asks,
        signals: record.signals,
        cancel_state: record.cancel_state,
    }
}
