//! The read check a task ask runs on each question and context ref
//! (`validate_task_answer_unit`), for the reader-class test
//! (FIX-LIST [ASK-READER-KEY-CLASSLESS]).

use crate::{EntityId, Error, Result, Vault};

/// Whether `unit` passes a task ask's read check for `principal` (the
/// asker) and `holder` (the recipient), in one read snapshot: `Ok(false)`
/// when it reads as absent to either party, the ask's refusal.
pub fn task_answer_unit_admitted(
    vault: &Vault,
    principal: EntityId,
    holder: EntityId,
    unit: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    match crate::llm::decision::questions::validate_task_answer_unit(
        vault, &txn, principal, holder, unit,
    ) {
        Ok(_) => Ok(true),
        Err(Error::EntityNotFound) => Ok(false),
        Err(error) => Err(error),
    }
}
