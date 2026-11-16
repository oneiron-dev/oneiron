//! Cursor text that a paged list hands its client and reads back (UC-13).
//!
//! A client holds a cursor between pages, so a grammar here keeps the exact
//! spelling its lists already write. Each list refuses a cursor that does
//! not parse with its own error, so the text a client reads stays the list's.

use crate::entity_id::EntityId;

/// The `{at}:{id}` cursor: the time and entity id of a page's last place,
/// the id in lowercase hex. The mail inbox and the conversation transcript
/// write it.
pub fn join_at_id(at: u64, id: EntityId) -> String {
    format!("{at}:{}", id.to_hex())
}

/// Reads a [`join_at_id`] cursor back; `None` when the text is not one.
/// The text splits at its first `:`. The time reads as `u64::from_str`
/// reads it, and the id as [`EntityId::from_hex`] reads it, in either case.
pub fn split_at_id(cursor: &str) -> Option<(u64, EntityId)> {
    let (at, id) = cursor.split_once(':')?;
    Some((at.parse().ok()?, EntityId::from_hex(id).ok()?))
}

/// The `N` bytes of a hex cursor: exactly `2 * N` hex digits. A cursor
/// comes back as a request param, so it reads in either case
/// (HEX-CASE-POLICY = A); every list writes it in lowercase. `None` for
/// anything else, a sign or a space included.
pub fn parse_hex_cursor<const N: usize>(cursor: &str) -> Option<[u8; N]> {
    oneiron_hex::decode_any_case(cursor)
}

/// [`parse_hex_cursor`] for a cursor whose length varies: the bytes of an
/// even count of hex digits of either case (`""` gives no bytes).
pub fn parse_hex_cursor_vec(cursor: &str) -> Option<Vec<u8>> {
    oneiron_hex::decode_vec_any_case(cursor)
}
