//! A door for `tests/stream_seed_sitting.rs` (FIX 1033): the sitting a TURN
//! joined, read from its TURN → SESSION membership row (DREAM-008).

use crate::error::Result;
use crate::{EntityId, Vault};

/// The SESSION `turn` was witnessed into, or `None` when its witness
/// recorded no membership.
pub fn turn_sitting(vault: &Vault, turn: &EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, turn)
}
