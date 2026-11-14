//! Test doors for `tests/code_check_record.rs`: the bound checkout's worktree
//! path and the TASK's request revision. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::path::PathBuf;

use crate::EntityId;
use crate::checkout::lease::load_act_in_txn;
use crate::error::{Error, Result};
use crate::git_wire::GitWire;
use crate::store::checkout_lease::{CheckoutError, CheckoutId};
use crate::vault::Vault;

/// A checkout failure as the test reads it: a store failure as it is, anything else as not found.
fn checkout_error(error: CheckoutError) -> Error {
    match error {
        CheckoutError::Store(error) => error,
        _ => Error::EntityNotFound,
    }
}

/// The worktree path of the `checkout`.`epoch` lease: what the run's bound checkout materialized.
pub fn check_record_worktree_path(vault: &Vault, checkout: &str, epoch: u64) -> Result<PathBuf> {
    let entity = EntityId::from_hex(checkout).map_err(|_| Error::InvalidKey)?;
    let id = CheckoutId::from_bytes(*entity.as_bytes()).map_err(checkout_error)?;
    let txn = vault.store.env.read_txn()?;
    let lease = load_act_in_txn(vault, &txn, id)
        .map_err(checkout_error)?
        .ok_or(Error::EntityNotFound)?;
    if lease.epoch != epoch {
        return Err(Error::EntityNotFound);
    }
    GitWire::new(vault)?
        .checkout_worktree_path(&lease)
        .map_err(checkout_error)
}

/// The TASK's request revision: what `start` and `finish` capture.
pub fn check_record_task_revision(vault: &Vault, task: EntityId) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    crate::task_verb::linear_store::task_revision_in_txn(&vault.store, &txn, task)
}
