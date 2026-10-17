//! Moving a formula's relative references by a row and column offset: what a
//! shared formula's member reads, its anchor's text written from the member's
//! cell. One tokenizer, the same reading as [`crate::xlfn`]: string literals,
//! quoted sheet names and structured references are never references, a name
//! before `(` is a call, and a name before `!` is a sheet. `$` anchors stay.

const MAX_COLUMN: i64 = 16_384;
const MAX_ROW: i64 = 1_048_576;

/// `formula` (as a person types it, without `=`) moved `rows` down and `cols`
/// right. `None` when a moved reference would leave the sheet: the member
/// would read `#REF!`, which the caller keeps as a read-only shared cell.
#[must_use]
pub(crate) fn shift_formula(formula: &str, rows: i64, cols: i64) -> Option<String> {
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b {
                    i += 1;
                    if i < bytes.len() && bytes[i] == b {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push_str(&formula[start..i]);
            continue;
        }
        if b == b'[' {
            let start = i;
            let mut depth = 1;
            i += 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\''
                    && i + 1 < bytes.len()
                    && matches!(bytes[i + 1], b'[' | b']' | b'#' | b'\'')
                {
                    i += 2;
                } else {
                    if bytes[i] == b'[' {
                        depth += 1;
                    }
                    if bytes[i] == b']' {
                        depth -= 1;
                    }
                    i += 1;
                }
            }
            out.push_str(&formula[start..i]);
            continue;
        }
        let ch = formula[i..].chars().next()?;
        if !(ch.is_alphanumeric() || matches!(ch, '_' | '\\' | '$')) {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        if ch.is_ascii_digit() && !number_could_be_row(bytes, i) {
            let end = number_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        let end = token_end(formula, i);
        let token = &formula[i..end];
        let next = next_char(bytes, end);
        if next == Some(b'(') || next == Some(b'!') {
            out.push_str(token);
            i = end;
            continue;
        }
        // A whole-column (`A:C`) or whole-row (`2:5`) range moves along
        // one axis; each side of it alone is not a reference.
        if bytes.get(end) == Some(&b':') {
            let second_end = token_end(formula, end + 1);
            let second = &formula[end + 1..second_end];
            if let (Some(a), Some(b)) = (column(token), column(second)) {
                out.push_str(&a.moved(cols, MAX_COLUMN, letters)?);
                out.push(':');
                out.push_str(&b.moved(cols, MAX_COLUMN, letters)?);
                i = second_end;
                continue;
            }
            if let (Some(a), Some(b)) = (row(token), row(second)) {
                out.push_str(&a.moved(rows, MAX_ROW, number)?);
                out.push(':');
                out.push_str(&b.moved(rows, MAX_ROW, number)?);
                i = second_end;
                continue;
            }
        }
        if let Some((col, line)) = cell(token) {
            out.push_str(&col.moved(cols, MAX_COLUMN, letters)?);
            out.push_str(&line.moved(rows, MAX_ROW, number)?);
        } else {
            out.push_str(token);
        }
        i = end;
    }
    Some(out)
}

/// One coordinate of a reference: its value and whether `$` fixes it.
#[derive(Clone, Copy)]
struct Part {
    fixed: bool,
    value: i64,
}

impl Part {
    fn moved(self, by: i64, max: i64, render: fn(i64) -> String) -> Option<String> {
        let value = if self.fixed {
            self.value
        } else {
            self.value + by
        };
        if !(1..=max).contains(&value) {
            return None;
        }
        Some(format!(
            "{}{}",
            if self.fixed { "$" } else { "" },
            render(value)
        ))
    }
}

/// The end of the identifier-like token at `start`: letters, digits, `_`,
/// `.`, `\` and `$`.
fn token_end(formula: &str, start: usize) -> usize {
    let mut end = start;
    for ch in formula[start..].chars() {
        if ch.is_alphanumeric() || matches!(ch, '_' | '.' | '\\' | '$') {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    end
}

fn next_char(bytes: &[u8], mut at: usize) -> Option<u8> {
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    bytes.get(at).copied()
}

/// Whether the digits at `at` may be one side of a whole-row range: the
/// first side (`2:` follows) or the second (`:` precedes).
fn number_could_be_row(bytes: &[u8], at: usize) -> bool {
    let mut end = at;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    bytes.get(end) == Some(&b':') || (at > 0 && bytes[at - 1] == b':')
}

/// The end of a numeric literal: digits, a decimal point, an exponent.
fn number_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
        end += 1;
    }
    if end < bytes.len() && matches!(bytes[end], b'e' | b'E') {
        let mut exp = end + 1;
        if exp < bytes.len() && matches!(bytes[exp], b'+' | b'-') {
            exp += 1;
        }
        if exp < bytes.len() && bytes[exp].is_ascii_digit() {
            end = exp;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
        }
    }
    end
}

fn fixed(text: &str) -> (bool, &str) {
    match text.strip_prefix('$') {
        Some(rest) => (true, rest),
        None => (false, text),
    }
}

/// `$AB` or `C`: one to three letters naming a sheet column.
fn column(text: &str) -> Option<Part> {
    let (fixed, letters) = fixed(text);
    if letters.is_empty() || letters.len() > 3 || !letters.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let value = letters.bytes().fold(0_i64, |value, b| {
        value * 26 + i64::from(b.to_ascii_uppercase() - b'A' + 1)
    });
    (value <= MAX_COLUMN).then_some(Part { fixed, value })
}

/// `$12` or `7`: a sheet row.
fn row(text: &str) -> Option<Part> {
    let (fixed, digits) = fixed(text);
    if digits.is_empty() || digits.len() > 7 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: i64 = digits.parse().ok()?;
    (1..=MAX_ROW)
        .contains(&value)
        .then_some(Part { fixed, value })
}

/// `$B$12`, `B$12`, `$B12` or `B12`.
fn cell(text: &str) -> Option<(Part, Part)> {
    let split = text
        .char_indices()
        .skip(1)
        .find(|&(_, ch)| ch == '$' || ch.is_ascii_digit())?
        .0;
    Some((column(&text[..split])?, row(&text[split..])?))
}

fn number(value: i64) -> String {
    value.to_string()
}

fn letters(mut col: i64) -> String {
    let mut out = Vec::new();
    while col > 0 {
        out.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}
