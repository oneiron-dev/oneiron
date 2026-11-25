//! Doors for `tests/room_home_retry_claim.rs` (HOMERETRY-CLAIM-AUTHOR = B):
//! plant a room claim row and read it raw, and merge a copy another machine
//! of this vault carried, so the test sees what the ROOMS_CLAIM actor scrub
//! and the carried-claim merge leave of an erased person.

use crate::error::Result;
use crate::workspace_roster::RoomClaimReceipt;
use crate::workspace_roster::room_claim_erase_doors as doors;
use crate::{EntityId, Vault};

/// Writes `claim` as its turn's claim row.
///
/// # Errors
///
/// A malformed turn id, and storage faults.
pub fn put_room_claim(vault: &Vault, claim: &RoomClaimReceipt) -> Result<()> {
    doors::put_claim(vault, claim)
}

/// `turn`'s claim row, raw.
///
/// # Errors
///
/// Storage faults.
pub fn room_claim(vault: &Vault, turn: EntityId) -> Result<Option<RoomClaimReceipt>> {
    doors::claim(vault, turn)
}

/// Merges `claim` as a carried copy, as replica sync merges one; the merge's
/// outcome by name: `written`, `held`, `conflict` or `refused`.
///
/// # Errors
///
/// Storage faults.
pub fn merge_carried_room_claim(vault: &Vault, claim: &RoomClaimReceipt) -> Result<&'static str> {
    doors::merge_carried_claim(vault, claim)
}
