//! The raw result body rows (`CODE_RUN_RAW_OUTPUT`): each row keyed by its
//! body's content handle, where its body is (in the row or in a body file),
//! the tag byte that says so and whether the row holds its body on its own.
//! The code run layer (`code_run`) writes and reads these rows and keeps
//! their codec; the store's retention sweep tests a row for an inline body,
//! and the body-envelope prune names a row by its key.

pub const STORED_INLINE: u8 = 0;
pub const STORED_FILE: u8 = 1;
/// The tag bit of a row that holds its body on its own (FIX 5399b), beside
/// its body's place.
pub const STORED_HELD: u8 = 2;

/// A stored row's place (its tag without the hold bit) and the bytes after
/// its tag; `None` for an empty row.
pub fn split_row(row: &[u8]) -> Option<(u8, &[u8])> {
    row.split_first()
        .map(|(tag, rest)| (tag & !STORED_HELD, rest))
}

/// Whether a raw result body row holds its body inline, whoever holds the
/// body.
pub fn code_run_row_inline(value: &[u8]) -> bool {
    matches!(split_row(value), Some((STORED_INLINE, _)))
}
