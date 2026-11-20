//! Doors for `tests/project_leader_home_room_reply.rs` (FIX
//! ROOM-CLAIM-HELD-AFTER-SPEECH-STANDING-ENDS, Engine ROOM-CLAIM-TAKEOVER =
//! A, 21 Nov 03:04; REVIEW-9956 P1-2): a turn's claim row as another machine
//! of the vault carries it, merged as the room-fact import merges it; the
//! claim the vault holds for a turn, as its room-fact mirror reads it; and
//! an actor's erase from the room turns it spoke. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;
use crate::workspace_roster::{
    RoomClaimReceipt, RoomSideRow, erase_turn_actor_in_txn, merge_replicated_side_row_in_txn,
    replicated_side_rows_in,
};
use crate::{EntityId, Vault};

/// Merges `claim` as another machine of this vault carried it. Returns the
/// merge's outcome by its name: `Written`, `Held`, `Conflict` or
/// `Refused(..)`.
pub fn merge_replicated_claim(vault: &Vault, claim: &RoomClaimReceipt) -> Result<String> {
    let row = RoomSideRow::Claim {
        claim: claim.clone(),
    };
    let mut wtxn = vault.store.env.write_txn()?;
    let merge = merge_replicated_side_row_in_txn(vault, &mut wtxn, &row)?;
    wtxn.commit()?;
    Ok(format!("{merge:?}"))
}

/// The claim this vault holds for `turn`.
pub fn held_claim(vault: &Vault, turn: EntityId) -> Result<Option<RoomClaimReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        replicated_side_rows_in(vault, &txn, turn, ENTITY_TYPE_TURN)?
            .into_iter()
            .find_map(|row| match row {
                RoomSideRow::Claim { claim } => Some(claim),
                _ => None,
            }),
    )
}

/// Erases `actor` from every room turn it spoke, as an actor erase does:
/// each such turn's actor then reads as the erased marker.
pub fn erase_turn_actor(vault: &Vault, actor: EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    erase_turn_actor_in_txn(vault, &mut wtxn, &actor)?;
    wtxn.commit()?;
    Ok(())
}
