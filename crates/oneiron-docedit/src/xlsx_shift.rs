//! Moving a formula's relative references by a row and column offset: what a
//! shared formula's member reads, its anchor's text written from the member's
//! cell; and retargeting its sheet prefixes when sheets are renamed or
//! deleted. One tokenizer, the same reading as [`crate::xlfn`]: string literals,
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

/// What a reference to one of the workbook's sheets becomes when its sheets
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SheetFate {
    Keep,
    Rename(String),
    /// The sheet is gone: its references read `#REF!`, as Excel's do.
    Delete,
}

/// `formula` with each sheet prefix (`Data!`, `'My data'!`, `Jan:Mar!`)
/// retargeted by `fate`, asked of each sheet name as written. `None` when no
/// prefix changed. A reference into another workbook (`[1]Data!A1`) stays;
/// a 3D prefix with a deleted end reads `#REF!`.
#[must_use]
pub fn retarget_sheets(formula: &str, fate: &dyn Fn(&str) -> SheetFate) -> Option<String> {
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut changed = false;
    let mut external = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            let end = quoted_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        if b == b'[' {
            let start = i;
            let mut depth = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'\'' if matches!(bytes.get(i + 1), Some(b'[' | b']' | b'#' | b'\'')) => i += 1,
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
                i += 1;
                if depth == 0 {
                    break;
                }
            }
            out.push_str(&formula[start..i]);
            // `[1]Data!` names a sheet of another workbook.
            external = true;
            continue;
        }
        let ch = formula[i..].chars().next()?;
        let (prefix, end) = if b == b'\'' {
            let end = quoted_end(bytes, i);
            if bytes.get(end) != Some(&b'!') || end < i + 2 {
                out.push_str(&formula[i..end]);
                i = end;
                continue;
            }
            let inner = formula[i + 1..end - 1].replace("''", "'");
            (inner, end)
        } else if ch.is_alphanumeric() || matches!(ch, '_' | '\\') {
            if ch.is_ascii_digit() {
                let end = number_end(bytes, i);
                out.push_str(&formula[i..end]);
                i = end;
                external = false;
                continue;
            }
            let mut end = token_end(formula, i);
            // `Jan:Mar!` is a 3D prefix; `A1:Data!B2` is a range.
            if bytes.get(end) == Some(&b':') && cell(&formula[i..end]).is_none() {
                let second = token_end(formula, end + 1);
                if second > end + 1 && bytes.get(second) == Some(&b'!') {
                    end = second;
                }
            }
            // `#REF!` is an error value, not a sheet.
            if bytes.get(end) != Some(&b'!') || (i > 0 && bytes[i - 1] == b'#') {
                out.push_str(&formula[i..end]);
                i = end;
                external = false;
                continue;
            }
            (formula[i..end].to_owned(), end)
        } else {
            out.push(ch);
            i += ch.len_utf8();
            external = false;
            continue;
        };
        let written = &formula[i..=end];
        i = end + 1;
        if std::mem::take(&mut external) || prefix.contains('[') {
            out.push_str(written);
            continue;
        }
        let ends: Vec<&str> = prefix.splitn(2, ':').collect();
        let fates: Vec<SheetFate> = ends.iter().map(|name| fate(name)).collect();
        if fates.iter().all(|fate| *fate == SheetFate::Keep) {
            out.push_str(written);
            continue;
        }
        changed = true;
        if fates.contains(&SheetFate::Delete) {
            out.push_str("#REF!");
            continue;
        }
        let names: Vec<&str> = ends
            .iter()
            .zip(&fates)
            .map(|(name, fate)| match fate {
                SheetFate::Rename(to) => to.as_str(),
                _ => name,
            })
            .collect();
        out.push_str(&sheet_prefix(&names.join(":")));
        out.push('!');
    }
    changed.then_some(out)
}

/// A sheet name as a reference writes it, quoted unless it is a plain
/// identifier that cannot read as a cell.
fn sheet_prefix(name: &str) -> String {
    let plain = name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        && cell(name).is_none()
        && !r1c1_like(name);
    if plain {
        return name.to_owned();
    }
    format!("'{}'", name.replace('\'', "''"))
}

/// `R`, `C12`, `R2C3`: what an R1C1 reference reads as.
fn r1c1_like(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let rest = upper.strip_prefix('R').unwrap_or(&upper);
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix('C').unwrap_or(rest);
    rest.trim_start_matches(|c: char| c.is_ascii_digit())
        .is_empty()
}

/// Past the closing quote of the string or quoted name opening at `start`;
/// a doubled quote is an escaped one.
fn quoted_end(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == quote {
            i += 1;
            if bytes.get(i) != Some(&quote) {
                return i;
            }
        }
        i += 1;
    }
    i
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
