//! An approved `tasks.cancel` proposal's settlement (FIX 8946): the cancel
//! its proposer could not make lands when an approval door approves it, in
//! the approving transaction, through the effects the cancel rungs run.
//! Entry: `settle_cancel_in_txn`.
//!
//! The proposal names its target as the door that wrote it did: a run-tree
//! branch cancel names its branch's attempt in `branch_ref`; otherwise
//! `target_ref` is the TASK's id under that TASK's subject, else a spawn's
//! attempt. An attempt's hex is never read as a TASK id. Mode `force`
//! forces a TASK's live realizations as the owner's rung does when the
//! approver is the TASK's creator, the one actor that rung forces for, or
//! the vault owner, whose approval of a force is the owner's own act (FIX
//! 11105); every other approved cancel lands as the soft rung's, asking a
//! running realization to land. The approval is
//! the cancel's authority, so no gate runs again, and the effect names the
//! approver, else the proposer when the door named no approver.
//! An effect that does not land is logged and leaves the approval as it is;
//! a cancel already applied changes nothing again.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptInterventionKind, AttemptQueue, InterveneAttempt};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::write_envelope::WriteActor;

use super::brief::decode_hex;
use super::consts::TASK_CANCEL_FORCE_MODE;
use super::consult_result::CancelTargetState;
use super::highway_post::{envelope_actor_class, proposer_of};
use super::rate_limit::task_create_owner_in;
use super::wire_decode::task_body_optional;

/// The proposal value key naming the run-tree branch a cancel stops.
pub(super) const BRANCH_REF_KEY: &str = "branch_ref";

/// What an approved cancel proposal stops.
enum CancelTarget {
    /// One run-tree branch, by its attempt.
    Branch(AttemptId),
    /// A TASK's live realizations.
    Task(EntityId),
    /// A spawn's realization, by its attempt.
    Spawn(AttemptId),
}

/// Lands the approved cancel proposal `claim` in `wtxn`, the approving
/// transaction, in a savepoint of its own (module docs). Never fails the
/// approval.
pub(super) fn settle_cancel_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) {
    if let Err(error) = settle_in_savepoint(vault, wtxn, claim, approver, now) {
        tracing::warn!(
            code = %error.code,
            "an approved cancel proposal did not land; the approval stands"
        );
    }
}

fn settle_in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> MemoryResult<()> {
    let (target, force) = cancel_target(claim)
        .ok_or_else(|| MemoryError::bad_request("a cancel proposal names no target"))?;
    let proposer = proposer_of(claim, approver)?;
    let actor = match approver {
        Some(approver) => approver,
        None => WriteActor::new(
            proposer,
            envelope_actor_class(claim).ok_or_else(|| {
                MemoryError::bad_request("a cancel proposal names no proposer class")
            })?,
        ),
    };
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    let mut savepoint = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(crate::Error::from)?;
    apply_in(&memory, &mut savepoint, target, force, now)?;
    savepoint.commit().map_err(crate::Error::from)?;
    Ok(())
}

/// The target and whether it is forced, as `claim`'s value names them.
fn cancel_target(claim: &ClaimBody) -> Option<(CancelTarget, bool)> {
    let Value::Map(entries) = &claim.value else {
        return None;
    };
    let text = |key: &str| {
        task_body_optional(entries, key)
            .ok()
            .flatten()
            .and_then(Value::as_str)
    };
    let force = text("mode") == Some(TASK_CANCEL_FORCE_MODE);
    if let Some(branch) = text(BRANCH_REF_KEY) {
        return Some((CancelTarget::Branch(attempt_id(branch)?), force));
    }
    let target = text("target_ref")?;
    let subject = match &claim.subject {
        ClaimSubject::Entity(subject) => Some(*subject),
        ClaimSubject::Edge { .. } => None,
    };
    match EntityId::from_hex(target)
        .ok()
        .filter(|task| Some(*task) == subject)
    {
        Some(task) => Some((CancelTarget::Task(task), force)),
        None => Some((CancelTarget::Spawn(attempt_id(target)?), force)),
    }
}

fn attempt_id(hex: &str) -> Option<AttemptId> {
    AttemptId::from_bytes(&decode_hex::<16>(hex)?).ok()
}

/// Stops `target` in `wtxn` as `memory`'s actor: forced only when `force`
/// asks it of a TASK that actor created, or that actor is the vault owner.
fn apply_in(
    memory: &Memory<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    target: CancelTarget,
    force: bool,
    now: u64,
) -> MemoryResult<()> {
    let queue = AttemptQueue::new(memory.vault());
    match target {
        CancelTarget::Branch(id) => {
            queue.intervene_in_txn(
                wtxn,
                InterveneAttempt {
                    id,
                    kind: AttemptInterventionKind::Cancel,
                    actor: memory.actor().to_hex(),
                    note: None,
                    now,
                },
            )?;
        }
        CancelTarget::Task(task)
            if force
                && (task_create_owner_in(memory.vault(), &*wtxn, task)?
                    == Some(memory.actor())
                    || crate::memory::actor_is_vault_owner_in_txn(
                        memory.vault(),
                        &*wtxn,
                        memory.actor(),
                        memory.actor_class(),
                    )?) =>
        {
            memory.force_cancel_task_in(wtxn, task, None, now)?;
        }
        CancelTarget::Task(task) => {
            let state = CancelTargetState {
                owned: true,
                task_ref: Some(task),
                attempts: Vec::new(),
                proposal_subject: task,
                target_ref: task.to_hex(),
            };
            memory.soft_cancel_in(wtxn, &state, now)?;
        }
        CancelTarget::Spawn(id) => {
            let Some(record) = queue.get_in_write_txn(&*wtxn, id)? else {
                return Ok(());
            };
            let state = CancelTargetState {
                owned: true,
                task_ref: None,
                attempts: vec![(id, record.state)],
                proposal_subject: memory.actor(),
                target_ref: super::presence_scan::attempt_hex(id),
            };
            memory.soft_cancel_in(wtxn, &state, now)?;
        }
    }
    Ok(())
}
