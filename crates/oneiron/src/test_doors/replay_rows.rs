//! Doors for `tests/replay_rows_seam.rs`, `tests/replay_split_rows.rs`, `tests/replay_narrow_reads.rs`
//! (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1, PR2 and PR4): the replay row's canonical
//! bytes as stored, this thread's written- and read-bytes totals, a run's item count,
//! how many of its items the historical lift sweep walks through the run's head, and the
//! narrow replay reads (a run's checkpoint count, outputs and bridge calls).
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::{CodeRunBridgeCall, CodeRunRawOutput};
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

/// This thread's total read replay bytes.
pub fn read_bytes() -> u64 {
    crate::code_run::replay_rows::read_bytes()
}

/// The step checkpoints `run`'s replay record holds, if present.
///
/// # Errors
///
/// Storage errors.
pub fn checkpoint_count(vault: &Vault, run: EntityId) -> Result<Option<u64>> {
    vault.code_run_replay_checkpoint_count(&run)
}

/// The outputs `run`'s replay record holds, if present.
///
/// # Errors
///
/// Storage errors.
pub fn outputs(vault: &Vault, run: EntityId) -> Result<Option<Vec<CodeRunRawOutput>>> {
    vault.code_run_replay_outputs(&run)
}

/// The bridge calls `run`'s replay record holds, if present.
///
/// # Errors
///
/// Storage errors.
pub fn bridge_calls(vault: &Vault, run: EntityId) -> Result<Option<Vec<CodeRunBridgeCall>>> {
    vault.code_run_replay_bridge_calls(&run)
}
