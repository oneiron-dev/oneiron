//! One permissive A1 core (FIX 9207, ruling B): trim + any case + `$` +
//! unbounded letters/digits + full consumption. NO bounds, NO case rejection,
//! NO order opinion: callers keep order + bounds + refusal policy in thin
//! wrappers.

/// One parsed cell: 1-based column and row with each part's `$` anchor. The
/// core is permissive: the row may be 0 and the column past `XFD`; wrappers
/// enforce their own bounds (ruling B). Row-first callers read `.row`/`.col`
/// by field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct A1 {
    pub col: u32,
    pub row: u32,
    pub col_fixed: bool,
    pub row_fixed: bool,
}

/// `B12`, `$B$12`, `b12`: trimmed, any case, one `$` before the letters
/// and/or the digits, 1+ letters and 1+ digits (checked `u32`, unbounded,
/// leading zeros ok), nothing else. `None` otherwise.
#[must_use]
pub fn parse_cell(text: &str) -> Option<A1> {
    let text = text.trim();
    let (col_fixed, rest) = match text.strip_prefix('$') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let split = rest.find(|c: char| !c.is_ascii_alphabetic())?;
    let (letters, digits) = rest.split_at(split);
    let (row_fixed, digits) = match digits.strip_prefix('$') {
        Some(rest) => (true, rest),
        None => (false, digits),
    };
    if letters.is_empty() || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut col: u32 = 0;
    for byte in letters.bytes() {
        col = col
            .checked_mul(26)?
            .checked_add(u32::from(byte.to_ascii_uppercase() - b'A') + 1)?;
    }
    Some(A1 {
        col,
        row: digits.parse::<u32>().ok()?,
        col_fixed,
        row_fixed,
    })
}

/// 1-based column letters: `1` is `A`, `27` is `AA`. `0` renders as `""`
/// (today's behaviour; no caller passes 0 -- kept, not hardened: R8).
#[must_use]
pub(crate) fn col_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        out.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `B12`.
#[must_use]
pub(crate) fn cell_text(col: u32, row: u32) -> String {
    format!("{}{row}", col_letters(col))
}

/// `$B$12` by parts: a `$` before the letters when `col_fixed`, before the
/// digits when `row_fixed`.
#[must_use]
pub(crate) fn cell_text_fixed(col: u32, row: u32, col_fixed: bool, row_fixed: bool) -> String {
    let (col_dollar, row_dollar) = (
        if col_fixed { "$" } else { "" },
        if row_fixed { "$" } else { "" },
    );
    format!("{col_dollar}{}{row_dollar}{row}", col_letters(col))
}

/// One side of a whole-column (`A:C`) or whole-row (`2:5`) line: its axis,
/// value and `$`. No bounds (ruling B: wrappers check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineSide {
    Col { col: u32, fixed: bool },
    Row { row: u32, fixed: bool },
}

/// `$AB`, `C`, `$12`, `7`: trimmed, any case, one `$`, all letters or all
/// digits (checked `u32`, unbounded, leading zeros ok). Mixed (`B2`), empty
/// or trailing text is `None`.
#[must_use]
pub(crate) fn parse_line_side(text: &str) -> Option<LineSide> {
    let text = text.trim();
    let (fixed, rest) = match text.strip_prefix('$') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if rest.is_empty() {
        return None;
    }
    if rest.bytes().all(|b| b.is_ascii_alphabetic()) {
        let mut col: u32 = 0;
        for byte in rest.bytes() {
            col = col
                .checked_mul(26)?
                .checked_add(u32::from(byte.to_ascii_uppercase() - b'A') + 1)?;
        }
        return Some(LineSide::Col { col, fixed });
    }
    if rest.bytes().all(|b| b.is_ascii_digit()) {
        return Some(LineSide::Row {
            row: rest.parse::<u32>().ok()?,
            fixed,
        });
    }
    None
}
