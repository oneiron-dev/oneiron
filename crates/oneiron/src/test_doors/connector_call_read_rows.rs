//! Doors for `tests/connector_call_read_rows_personal.rs` (FIX
//! CONNECTOR-CALL-VAULT-TEXT-UNCLASSED): seed a code run's read ledger and
//! read whether it was served person rows.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::code_run::{ExecutorStorage, ReadWorldUnknown};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;

/// Notes `rows` as served to `run` at one bridge position, each under top
/// scope and none conflicted.
///
/// # Errors
///
/// Storage errors.
pub fn note_read_rows_for_test(vault: &Vault, run: EntityId, rows: &[EntityId]) -> Result<()> {
    let scoped: BTreeMap<EntityId, Scope> = rows.iter().map(|row| (*row, Scope::top())).collect();
    ExecutorStorage::Canonical(vault).note_read_rows(run, 1, &scoped, &BTreeSet::new())
}

/// Marks `run`'s ledger as missing rows it was served.
///
/// # Errors
///
/// Storage errors.
pub fn mark_read_world_unknown_for_test(vault: &Vault, run: EntityId) -> Result<()> {
    ExecutorStorage::Canonical(vault).mark_read_world_unknown(run, ReadWorldUnknown::NotFromStart)
}

/// Whether `run` was served a vault row that can carry a person's words.
///
/// # Errors
///
/// Storage errors.
pub fn run_was_served_person_rows(vault: &Vault, run: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    vault.run_was_served_person_rows_in_txn(&txn, run)
}
