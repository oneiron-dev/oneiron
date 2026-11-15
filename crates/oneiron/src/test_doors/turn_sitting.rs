//! Doors for `tests/turn_action_reply_sitting.rs` and
//! `tests/turn_action_context_sitting.rs` (FIX 1034): the sitting a TURN
//! joined, read from and written to its TURN → SESSION membership row
//! (DREAM-008).

use crate::error::Result;
use crate::{EntityId, Vault};

/// The SESSION `turn` was witnessed into, or `None` when its witness
/// recorded no membership.
pub fn turn_sitting(vault: &Vault, turn: &EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, turn)
}

/// Records that `turn` joined `session`, as the terminal of a chat host's
/// session-bound stream records its reply in its caller's sitting
/// (memory/witness/stream/session.rs). A TURN that already joined one keeps
/// it (first write wins). Returns the sitting the TURN holds.
pub fn join_turn_to_sitting(
    vault: &Vault,
    turn: &EntityId,
    session: &EntityId,
) -> Result<Option<EntityId>> {
    vault.with_write_txn(|txn| {
        crate::compaction::record_turn_session_membership_in_txn(
            &vault.store,
            txn,
            turn,
            Some(*session),
        )
    })
}
