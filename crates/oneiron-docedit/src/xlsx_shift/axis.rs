//! Moving a formula's references into one sheet when rows or columns are
//! inserted or deleted there: the edit, where it sends a row, a column, a
//! cell and an area, and the formula rewritten by it.

use super::{
    MAX_COLUMN, MAX_ROW, Part, cell, column, letters, next_char, number_could_be_row, number_end,
    quoted_end, row, token_end,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
