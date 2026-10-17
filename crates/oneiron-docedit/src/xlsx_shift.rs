//! Moving a formula's relative references by a row and column offset: what a
//! shared formula's member reads, its anchor's text written from the member's
//! cell; retargeting its sheet prefixes when sheets are renamed or deleted;
//! and moving its references into one sheet when rows or columns are inserted
//! or deleted there. One tokenizer, the same reading as [`crate::xlfn`]:
//! string literals, quoted sheet names and structured references are never
//! references, a name before `(` is a call, and a name before `!` is a sheet.
//! `$` anchors stay.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

/// Which way a row or column edit runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxAxis {
    Row,
    Column,
}

/// `count` rows or columns inserted before, or deleted from, row or column
/// `at` of one worksheet; both 1-based, so column C is 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxAxisEdit {
    pub axis: XlsxAxis,
    pub at: u32,
    pub count: u32,
    pub delete: bool,
}

impl XlsxAxisEdit {
    /// Whether the edit is on the sheet: at least one row or column, starting
    /// on the sheet and, for a delete, ending on it.
    #[must_use]
    pub fn fits(&self) -> bool {
        let max = self.max();
        self.count >= 1
            && (1..=max).contains(&self.at)
            && self.count <= max
            && (!self.delete || self.at - 1 + self.count <= max)
    }

    fn max(&self) -> u32 {
        match self.axis {
            XlsxAxis::Row => MAX_ROW as u32,
            XlsxAxis::Column => MAX_COLUMN as u32,
        }
    }

    /// Where row or column `n` lands; `None` when the edit deletes it or an
    /// insert pushes it off the sheet.
    #[must_use]
    pub fn moved(&self, n: u32) -> Option<u32> {
        if n < self.at {
            return Some(n);
        }
        if self.delete {
            return (n - self.at >= self.count).then(|| n - self.count);
        }
        n.checked_add(self.count).filter(|to| *to <= self.max())
    }

    /// Where the span `first..=last` lands. An insert moves each end at or
    /// past `at`, so one inside the span widens it, and a last end pushed off
    /// the sheet stops at its edge. A delete shrinks it by what it loses.
    /// `None` when it loses everything, or an insert pushes all of it off.
    #[must_use]
    pub fn range(&self, first: u32, last: u32) -> Option<(u32, u32)> {
        if !self.delete {
            return Some((self.moved(first)?, self.moved(last).unwrap_or(self.max())));
        }
        let end = self.at + self.count - 1;
        let first = match first {
            first if first < self.at => first,
            first if first > end => first - self.count,
            _ => self.at,
        };
        let last = match last {
            last if last < self.at => last,
            last if last > end => last - self.count,
            _ => self.at - 1,
        };
        (first <= last).then_some((first, last))
    }

    /// A cell, `(column, row)`, after the edit.
    #[must_use]
    pub fn cell(&self, (col, row): (u32, u32)) -> Option<(u32, u32)> {
        match self.axis {
            XlsxAxis::Row => Some((col, self.moved(row)?)),
            XlsxAxis::Column => Some((self.moved(col)?, row)),
        }
    }

    /// A rectangle's `(column, row)` corners after the edit.
    #[must_use]
    pub fn area(&self, first: (u32, u32), last: (u32, u32)) -> Option<((u32, u32), (u32, u32))> {
        match self.axis {
            XlsxAxis::Row => {
                let (top, bottom) = self.range(first.1, last.1)?;
                Some(((first.0, top), (last.0, bottom)))
            }
            XlsxAxis::Column => {
                let (left, right) = self.range(first.0, last.0)?;
                Some(((left, first.1), (right, last.1)))
            }
        }
    }
}

/// `formula` with each reference into worksheet `sheet` moved by `edit`, as
/// Excel moves it when rows or columns are inserted or deleted: `$` anchors
/// move too and stay written. A reference without a sheet prefix is into
/// `home`. A deleted reference reads `#REF!` after its prefix, a range that
/// loses part of itself shrinks, and 3D and external references stay.
/// `None` when nothing moved.
#[must_use]
pub fn shift_axis(
    formula: &str,
    home: Option<&str>,
    sheet: &str,
    edit: &XlsxAxisEdit,
) -> Option<String> {
    let sheet = sheet.to_lowercase();
    let same = |name: &str| name.to_lowercase() == sheet;
    let at_home = home.is_some_and(same);
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut external = false;
    // Whether the reference after a prefix just read is into `sheet`.
    let mut target: Option<bool> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            let end = quoted_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            (target, external) = (None, false);
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
            (target, external) = (None, true);
            continue;
        }
        if b == b'\'' {
            let end = quoted_end(bytes, i);
            if bytes.get(end) == Some(&b'!') && end >= i + 2 {
                let inner = formula[i + 1..end - 1].replace("''", "'");
                out.push_str(&formula[i..=end]);
                i = end + 1;
                target = Some(
                    !std::mem::take(&mut external) && !inner.contains(['[', ':']) && same(&inner),
                );
            } else {
                out.push_str(&formula[i..end]);
                i = end;
                (target, external) = (None, false);
            }
            continue;
        }
        let ch = formula[i..].chars().next()?;
        if !(ch.is_alphanumeric() || matches!(ch, '_' | '\\' | '$')) {
            out.push(ch);
            i += ch.len_utf8();
            (target, external) = (None, false);
            continue;
        }
        if ch.is_ascii_digit() && !number_could_be_row(bytes, i) {
            let end = number_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            (target, external) = (None, false);
            continue;
        }
        let start = i;
        let end = token_end(formula, i);
        let token = &formula[i..end];
        // `Jan:Mar!` is a 3D prefix, which stays; `A1:B2` is a range.
        if bytes.get(end) == Some(&b':') && cell(token).is_none() {
            let second = token_end(formula, end + 1);
            if second > end + 1 && bytes.get(second) == Some(&b'!') {
                out.push_str(&formula[i..=second]);
                i = second + 1;
                (target, external) = (Some(false), false);
                continue;
            }
        }
        if bytes.get(end) == Some(&b'!') {
            // `#REF!` is an error value, whose reference stays.
            let error = i > 0 && bytes[i - 1] == b'#';
            out.push_str(&formula[i..=end]);
            i = end + 1;
            target = Some(
                !error && !std::mem::take(&mut external) && !token.contains('[') && same(token),
            );
            continue;
        }
        let ours = target.take().unwrap_or(at_home);
        external = false;
        if next_char(bytes, end) == Some(b'(') {
            out.push_str(token);
            i = end;
            continue;
        }
        if bytes.get(end) == Some(&b':') {
            let second_end = token_end(formula, end + 1);
            let second = &formula[end + 1..second_end];
            // `(first end, second end, axis, whether the ends are cells)`.
            let pair = if let (Some(a), Some(b)) = (column(token), column(second)) {
                Some((a, b, XlsxAxis::Column, false))
            } else if let (Some(a), Some(b)) = (row(token), row(second)) {
                Some((a, b, XlsxAxis::Row, false))
            } else if let (Some((a_col, a_row)), Some((b_col, b_row))) = (cell(token), cell(second))
            {
                Some(match edit.axis {
                    XlsxAxis::Row => (a_row, b_row, XlsxAxis::Row, true),
                    XlsxAxis::Column => (a_col, b_col, XlsxAxis::Column, true),
                })
            } else {
                None
            };
            if let Some((a, b, axis, cells)) = pair {
                i = second_end;
                if !ours || axis != edit.axis {
                    out.push_str(&formula[start..second_end]);
                    continue;
                }
                let (first, last) = (a.value as u32, b.value as u32);
                let Some((low, high)) = edit.range(first.min(last), first.max(last)) else {
                    out.push_str("#REF!");
                    continue;
                };
                let (first, last) = if first <= last {
                    (low, high)
                } else {
                    (high, low)
                };
                out.push_str(&rewritten(token, a, first, axis, cells));
                out.push(':');
                out.push_str(&rewritten(second, b, last, axis, cells));
                continue;
            }
        }
        i = end;
        match cell(token) {
            Some((col, line)) if ours => {
                let part = match edit.axis {
                    XlsxAxis::Row => line,
                    XlsxAxis::Column => col,
                };
                match edit.moved(part.value as u32) {
                    Some(to) => out.push_str(&rewritten(token, part, to, edit.axis, true)),
                    None => out.push_str("#REF!"),
                }
            }
            _ => out.push_str(token),
        }
    }
    (out != formula).then_some(out)
}

/// One end of a reference, as written, with its `axis` coordinate `part`
/// moved to `to`. A cell keeps its other coordinate, and `$` stays.
fn rewritten(text: &str, part: Part, to: u32, axis: XlsxAxis, cell: bool) -> String {
    if i64::from(to) == part.value {
        return text.to_owned();
    }
    let dollar = if part.fixed { "$" } else { "" };
    let split = if cell {
        text.char_indices()
            .skip(1)
            .find(|&(_, ch)| ch == '$' || ch.is_ascii_digit())
            .map_or(text.len(), |(at, _)| at)
    } else {
        0
    };
    match axis {
        XlsxAxis::Row => format!("{}{dollar}{to}", &text[..split]),
        XlsxAxis::Column if cell => format!("{dollar}{}{}", letters(i64::from(to)), &text[split..]),
        XlsxAxis::Column => format!("{dollar}{}", letters(i64::from(to))),
    }
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
