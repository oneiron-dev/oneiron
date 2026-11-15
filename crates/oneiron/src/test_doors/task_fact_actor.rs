//! Door for `tests/task_fact_actor_rule.rs` (Fable pass 28 R5 part 2): writes one TASK
//! authority fact under this install's carrier, through the mint door or past its actor
//! check, and reads what a TASK's facts prove about who may act on it.

use crate::error::Result;
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
    write_unjudged_task_authority_fact_in_txn,
};
use crate::{EntityId, Vault};

/// What one TASK's facts prove: its owner, the actor it is addressed to, and its latest
/// taker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvedStanding {
    /// The actor the Owner fact names.
    pub owner: EntityId,
    /// The Assigned fact's assignee, else the human-assignment witness's agent.
    pub assignee: Option<EntityId>,
    /// The latest Accepted fact's actor.
    pub taker: Option<EntityId>,
}

fn fact_at(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
    assigned: Option<EntityId>,
) -> Result<TaskAuthorityFact> {
    Ok(TaskAuthorityFact {
        task_ref: task,
        kind,
        actor_ref: actor,
        assigned_ref: assigned,
        actor_generation: None,
        assigned_generation: None,
        occurred_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        maker: None,
    })
}

/// Mints `actor`'s `kind` fact about `task` through the mint door, naming `assigned` where
/// the kind names one.
///
/// # Errors
///
/// As `put_task_authority_fact_in_txn`, which refuses an actor that may not make the fact.
pub fn mint_fact(
    vault: &Vault,
    task: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
    assigned: Option<EntityId>,
) -> Result<EntityId> {
    vault.with_write_txn(|txn| {
        let fact = fact_at(vault, txn, task, kind, actor, assigned)?;
        put_task_authority_fact_in_txn(vault, txn, fact)
    })
}

/// [`mint_fact`] past the door's actor check: the fact a member machine whose door lacks
/// the check would carry, signed by this install's carrier.
///
/// # Errors
///
/// As the fact's write.
pub fn write_unjudged_fact(
    vault: &Vault,
    task: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
    assigned: Option<EntityId>,
) -> Result<EntityId> {
    vault.with_write_txn(|txn| {
        let fact = fact_at(vault, txn, task, kind, actor, assigned)?;
        write_unjudged_task_authority_fact_in_txn(vault, txn, fact)
    })
}

/// What `task`'s facts prove about who may act on it, or `None` when no Owner fact proves
/// an owner.
///
/// # Errors
///
/// As the task's fact read: a forked owner or assignment fails it.
pub fn proved_standing(vault: &Vault, task: EntityId) -> Result<Option<ProvedStanding>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .task_standing_in(&txn, task)?
        .map(|standing| ProvedStanding {
            owner: standing.owner,
            assignee: standing.assignee,
            taker: standing.taker.map(|taker| taker.actor),
        }))
}
