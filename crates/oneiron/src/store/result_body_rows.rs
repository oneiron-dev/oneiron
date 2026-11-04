//! The tag byte of a raw result body row: where its body is (in the row or
//! in a body file) and whether the row holds its body on its own. The code
//! run layer (`code_run`) writes and reads these rows; the store's retention
//! sweep tests a row for an inline body.

pub(crate) const STORED_INLINE: u8 = 0;
pub(crate) const STORED_FILE: u8 = 1;
/// The tag bit of a row that holds its body on its own (FIX 5399b), beside
/// its body's place.
pub(crate) const STORED_HELD: u8 = 2;

/// A stored row's place (its tag without the hold bit) and the bytes after
/// its tag; `None` for an empty row.
pub(crate) fn split_row(row: &[u8]) -> Option<(u8, &[u8])> {
    row.split_first()
        .map(|(tag, rest)| (tag & !STORED_HELD, rest))
}

/// Whether a raw result body row holds its body inline, whoever holds the
/// body.
pub(crate) fn code_run_row_inline(value: &[u8]) -> bool {
    matches!(split_row(value), Some((STORED_INLINE, _)))
}
