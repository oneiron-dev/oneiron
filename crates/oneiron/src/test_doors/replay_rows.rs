//! Doors for `tests/replay_rows_seam.rs` and `tests/replay_split_rows.rs`
//! (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1 and PR2): the replay row's canonical
//! bytes as stored, this thread's written-bytes total, a run's item count, and
//! how many of its items the historical lift sweep walks through the run's head.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// The replay row's canonical bytes for `run`, if present.
///
/// # Errors
///
/// Storage errors.
pub fn canonical_bytes(vault: &Vault, run: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    crate::code_run::replay_rows::canonical_bytes(&vault.store, &txn, &run)
}

/// This thread's total written replay bytes.
pub fn written_bytes() -> u64 {
    crate::code_run::replay_rows::written_bytes()
}

/// The item rows of `run`, in every family.
///
/// # Errors
///
/// Storage errors.
pub fn item_count(vault: &Vault, run: EntityId) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    crate::code_run::replay_rows::item_count(&vault.store, &txn, &run)
}

/// How many of `run`'s item rows the historical lift sweep walks and admits
/// through the run's head origin. The transaction is aborted: nothing is written.
///
/// # Errors
///
/// Storage errors.
pub fn lift_routed_items(vault: &Vault, run: EntityId) -> Result<u64> {
    let mut txn = vault.store.env.write_txn()?;
    let routed = crate::code_run::replay_rows::lift_routed_items(&vault.store, &mut txn, &run)?;
    txn.abort();
    Ok(routed)
}
