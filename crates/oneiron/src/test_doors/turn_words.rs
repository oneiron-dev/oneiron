//! Doors for `tests/turn_words_edge_rewire.rs`: whether a TURN holds a re-dirty
//! carrier pending for every consolidation scope, and the embedding marker its
//! words owe, neither of which has a public read; a TURN's stored row, so a
//! batch can put it again as it stands; and every scope's watermark settled
//! on a TURN, as rounds that read it would leave it.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::{TimeRange, Vault};

/// Whether `turn` is live and holds a re-dirty carrier pending for every
/// consolidation scope (Micro, Meso and Macro).
///
/// # Errors
///
/// The reads.
pub fn redirty_pending(vault: &Vault, turn: &EntityId) -> Result<bool> {
    crate::dreamer_consolidation::redirty::pending_for_every_scope(vault, turn)
}

/// The embedding marker `turn` owes, when one is pending. It commits to the
/// turn's words at the write that marked it, so a mark at other words gives
/// another marker.
///
/// # Errors
///
/// The read.
pub fn embedding_marker(vault: &Vault, turn: &EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    vault.store.pending_embedding_token(&txn, turn)
}

/// `turn`'s stored row as it stands: its occurred range, its learned-at key
/// and its body, when a row is stored.
///
/// # Errors
///
/// The read.
pub fn stored_turn(vault: &Vault, turn: &EntityId) -> Result<Option<(TimeRange, u64, Vec<u8>)>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .port_entity_record(&txn, turn)?
        .map(|row| (row.occurred, row.learned_at, row.body)))
}

/// Settles every consolidation scope's watermark on `turn`'s key, as a round
/// of each that read it would.
///
/// # Errors
///
/// The read and the watermark writes.
pub fn settle_every_scope_on_turn(vault: &Vault, turn: &EntityId) -> Result<()> {
    crate::dreamer_consolidation::redirty::settle_every_scope_on_turn(vault, turn)
}
