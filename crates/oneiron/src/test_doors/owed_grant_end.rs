//! A Grant end this install owes (pass 28 R3e, FIX [R3E-FAMILYLESS-DEBT-NEEDS-DOORS]), for
//! `tests/grant_review_fix_pins.rs`: a peer's soft delete of a Grant row replayed here, the
//! carry pass over every owed end, and whether an end is still owed for one Grant.

use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::{EntityId, Result, Vault};

/// Replays a peer's user delete of the row `id` (a soft erase: no hard-delete marker) into
/// this vault, as a sync tombstone replay lands it, in one write at the vault clock.
///
/// # Errors
///
/// A store failure.
pub fn replay_peer_soft_delete(vault: &Vault, id: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let tombstone = TombstoneValueV2 {
            reason: TombstoneReason::UserDelete,
            deleted_at: vault.instant_in_txn(txn)?.secs(),
            request_id: [0x5a; 16],
        }
        .encode();
        vault
            .apply_replayed_tombstone_in_txn(txn, &id, &tombstone)
            .map(drop)
    })
}

/// Runs the pass that carries every Grant end this install owes and can sign or clear now, as
/// the install key's load runs it; a debt that waits stays owed.
pub fn carry_owed_grant_ends(vault: &Vault) {
    vault.carry_owed_grant_ends_logged();
}

/// Whether this install still owes a counted end for the Grant `grant`.
///
/// # Errors
///
/// A store read failure.
pub fn grant_end_owed(vault: &Vault, grant: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::federation::grant_end_owed_in_txn(
        &vault.store,
        &txn,
        grant,
    ))
}
