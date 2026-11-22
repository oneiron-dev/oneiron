//! Doors for the question read regressions: exact graph-neighbourhood
//! controls for the standing graph owner read, and the read check a task ask
//! runs on each question and context ref (FIX-LIST [ASK-READER-KEY-CLASSLESS]).

use crate::claim::ScopedReadActorKey;
use crate::llm::decision::questions::{question_lane, validate_task_answer_unit};
use crate::{EntityId, Error, Result, Vault};

/// Read as a question's bare human identity, with or without its owner alternative.
pub fn neighbors(
    vault: &Vault,
    reader: EntityId,
    unit: &EntityId,
    own_owner_authority: bool,
) -> Result<Option<Vec<EntityId>>> {
    // Match saved_reader -> asker_reader_in_txn for a live PERSON and a
    // question saved with FrozenReadLane::principal().
    let key = ScopedReadActorKey::with_actor_class(reader.to_hex(), "human")
        .ok_or(Error::InvariantViolation("canonical ask principal"))?
        .exempt_while_owner(reader);
    let lane = if own_owner_authority {
        question_lane(vault, key)
    } else {
        vault.scoped_read(key)
    };
    // The same bounds as graph_ask::unit_context.
    Ok(lane
        .graph_ask_neighbors(unit, 16, 4096, 1_048_576)?
        .map(|neighbors| neighbors.into_iter().map(|(id, _, _)| id).collect()))
}

/// Whether `unit` passes a task ask's read check (`validate_task_answer_unit`)
/// for `principal` (the asker) and `holder` (the recipient), in one read
/// snapshot: `Ok(false)` when it reads as absent to either party, the ask's
/// refusal.
pub fn task_answer_unit_admitted(
    vault: &Vault,
    principal: EntityId,
    holder: EntityId,
    unit: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    match validate_task_answer_unit(vault, &txn, principal, holder, unit) {
        Ok(_) => Ok(true),
        Err(Error::EntityNotFound) => Ok(false),
        Err(error) => Err(error),
    }
}
