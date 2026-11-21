//! Doors for `tests/replay_rows_seam.rs` (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1):
//! the replay row's canonical bytes as stored, and this thread's written-bytes
//! total. Compiled only under `--cfg oneiron_test_support`; never API.

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
