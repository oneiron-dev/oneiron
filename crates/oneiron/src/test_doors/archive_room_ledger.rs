//! Doors for `tests/archive_import_owner_installs_room_membership.rs` (REVIEW-9446 P1-3,
//! P1-4): a source room ledger the membership door never writes, so the source's whole-vault
//! archive carries one. Not API.

use crate::{EntityId, Result, Vault};

/// Deletes room `room`'s ledger revision row and keeps its rows.
///
/// # Errors
///
/// The store's.
pub fn drop_room_ledger_sequence(vault: &Vault, room: EntityId) -> Result<()> {
    crate::conversation::archive_restore::ledger_test_support::drop_sequence(vault, room)
}

/// Rewrites row `ordinal` of room `room`'s ledger with `visible_from`.
///
/// # Errors
///
/// The store's, or `InvariantViolation` when the room holds no such row.
pub fn set_room_ledger_row_visible_from(
    vault: &Vault,
    room: EntityId,
    ordinal: u64,
    visible_from: Option<u64>,
) -> Result<()> {
    crate::conversation::archive_restore::ledger_test_support::set_row_visible_from(
        vault,
        room,
        ordinal,
        visible_from,
    )
}
