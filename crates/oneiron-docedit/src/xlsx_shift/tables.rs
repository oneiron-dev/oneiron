//! Rewriting a formula's structured references when a table loses columns,
//! a column's header changes or the table itself goes.

use super::{quoted_end, token_end};
use std::collections::HashSet;

/// `formula` with each structured reference to table `table` that names one
/// of its `deleted` columns rewritten as Excel does when the columns go: a
/// reference naming a deleted column reads `#REF!`, and a column span
/// (`Sales[[Jan]:[Mar]]`) that keeps some of its columns shrinks to them.
/// `columns` is the table's columns before the edit, left to right. Names
/// compare without case. An unqualified reference (`[@Price]`, `[Price]`)
/// is to the table the formula belongs to, so it is rewritten only when
/// that is this table (`own`, FIX 3438). One into another workbook stays.
/// `None` when nothing changed.
#[must_use]
pub(crate) fn drop_table_columns(
    formula: &str,
    table: &str,
    columns: &[String],
    deleted: &[String],
    own: bool,
) -> Option<String> {
    let table = table.to_lowercase();
    let gone: HashSet<String> = deleted.iter().map(|name| name.to_lowercase()).collect();
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let end = quoted_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        if b == b'[' {
            let end = bracket_end(bytes, i);
            let dropped = (own && !workbook_prefix(formula, end))
                .then(|| drop_columns(&formula[i..end], columns, &gone))
                .flatten();
            match dropped {
                Some(Some(rewritten)) => out.push_str(&rewritten),
                Some(None) => out.push_str("#REF!"),
                None => out.push_str(&formula[i..end]),
            }
            i = end;
            continue;
        }
        let ch = formula[i..].chars().next()?;
        if !(ch.is_alphanumeric() || matches!(ch, '_' | '\\')) {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let end = token_end(formula, i);
        let name = &formula[i..end];
        // `[1]!Sales[Price]` is another workbook's table.
        let external = i > 0 && bytes[i - 1] == b'!';
        if bytes.get(end) != Some(&b'[') {
            out.push_str(name);
            i = end;
            continue;
        }
        let close = bracket_end(bytes, end);
        // Another table's or workbook's structured reference stays whole.
        if external || name.to_lowercase() != table {
            out.push_str(&formula[i..close]);
            i = close;
            continue;
        }
        match drop_columns(&formula[end..close], columns, &gone) {
            Some(Some(rewritten)) => {
                out.push_str(name);
                out.push_str(&rewritten);
            }
            Some(None) => out.push_str("#REF!"),
            None => out.push_str(&formula[i..close]),
        }
        i = close;
    }
    (out != formula).then_some(out)
}

/// Whether the bracket closing at `end` opens a reference into another
/// workbook (`[1]Data!A1`, `[1]!Name`, `[Book.xlsx]Data!A1`) rather than
/// being a structured reference.
fn workbook_prefix(formula: &str, end: usize) -> bool {
    formula[end..]
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || matches!(c, '!' | '\'' | '_' | '\\' | '$'))
}

/// `formula` with each structured reference to column `old` of table
/// `table` naming `new` instead, as Excel rewrites them when the column's
/// header changes (FIX 6399): `Sales[Old]`, `Sales[[#This Row],[Old]]`, a
/// column span's end, and an unqualified `[@Old]` when the formula belongs
/// to the table (`own`). Names compare without case; string literals,
/// other tables and other workbooks stay. `None` when nothing changed.
#[must_use]
pub(crate) fn rename_table_column(
    formula: &str,
    table: &str,
    old: &str,
    new: &str,
    own: bool,
) -> Option<String> {
    let table = table.to_lowercase();
    let old = old.to_lowercase();
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let end = quoted_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        if b == b'[' {
            let end = bracket_end(bytes, i);
            let renamed = (own && !workbook_prefix(formula, end))
                .then(|| rename_column(&formula[i..end], &old, new))
                .flatten();
            out.push_str(renamed.as_deref().unwrap_or(&formula[i..end]));
            i = end;
            continue;
        }
        let ch = formula[i..].chars().next()?;
        if !(ch.is_alphanumeric() || matches!(ch, '_' | '\\')) {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let end = token_end(formula, i);
        let name = &formula[i..end];
        let external = i > 0 && bytes[i - 1] == b'!';
        if bytes.get(end) != Some(&b'[') {
            out.push_str(name);
            i = end;
            continue;
        }
        let close = bracket_end(bytes, end);
        if external || name.to_lowercase() != table {
            out.push_str(&formula[i..close]);
            i = close;
            continue;
        }
        out.push_str(name);
        match rename_column(&formula[end..close], &old, new) {
            Some(renamed) => out.push_str(&renamed),
            None => out.push_str(&formula[end..close]),
        }
        i = close;
    }
    (out != formula).then_some(out)
}

/// One structured reference's brackets with each item naming column `old`
/// (lower case) naming `new`; `None` when it names no such item.
fn rename_column(text: &str, old: &str, new: &str) -> Option<String> {
    if text.len() < 2 || !text.ends_with(']') {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    let bytes = inner.as_bytes();
    if bracket_at(bytes).is_none() {
        let (at, raw) = match inner.strip_prefix('@') {
            Some(raw) => ("@", raw),
            None => ("", inner),
        };
        if raw.starts_with('#') || unescape(raw).to_lowercase() != old {
            return None;
        }
        return Some(format!("[{at}{}]", escape(new)));
    }
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut j = 0;
    while j < bytes.len() {
        if bytes[j] != b'[' {
            j += 1;
            continue;
        }
        let end = bracket_end(bytes, j);
        let raw = inner.get(j + 1..end.saturating_sub(1)).unwrap_or_default();
        if !raw.starts_with('#') && unescape(raw).to_lowercase() == old {
            edits.push((j..end, format!("[{}]", escape(new))));
        }
        j = end;
    }
    if edits.is_empty() {
        return None;
    }
    let mut out = inner.to_owned();
    for (range, name) in edits.into_iter().rev() {
        out.replace_range(range, &name);
    }
    Some(format!("[{out}]"))
}

/// `formula` with each reference to a table in `tables` (names in lower
/// case) reading `#REF!`, as Excel's does when the sheet holding the table
/// goes: a structured reference (`Sales[Price]`, `Sales[#All]`) or the bare
/// table name. A sheet prefix, a function and a reference into another
/// workbook stay. `None` when nothing changed.
#[must_use]
pub fn drop_tables(formula: &str, tables: &HashSet<String>) -> Option<String> {
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let end = quoted_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        if b == b'[' {
            let end = bracket_end(bytes, i);
            out.push_str(&formula[i..end]);
            i = end;
            continue;
        }
        let ch = formula[i..].chars().next()?;
        if !(ch.is_alphanumeric() || matches!(ch, '_' | '\\')) {
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let end = token_end(formula, i);
        let name = &formula[i..end];
        let next = bytes.get(end).copied();
        if (i > 0 && bytes[i - 1] == b'!')
            || matches!(next, Some(b'!' | b'('))
            || !tables.contains(&name.to_lowercase())
        {
            out.push_str(name);
            i = end;
            continue;
        }
        out.push_str("#REF!");
        i = if next == Some(b'[') {
            bracket_end(bytes, end)
        } else {
            end
        };
    }
    (out != formula).then_some(out)
}

/// One structured reference's brackets after columns `gone` (lower case)
/// leave a table whose columns were `columns`: `None` when it keeps them
/// all, `Some(None)` when it reads `#REF!`.
fn drop_columns(text: &str, columns: &[String], gone: &HashSet<String>) -> Option<Option<String>> {
    if text.len() < 2 || !text.ends_with(']') {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    let bytes = inner.as_bytes();
    // `[Price]` or `[@Price]`: one column, or a specifier such as `[#All]`.
    if bracket_at(bytes).is_none() {
        let raw = inner.strip_prefix('@').unwrap_or(inner);
        if raw.is_empty() || raw.starts_with('#') {
            return None;
        }
        return gone.contains(&unescape(raw).to_lowercase()).then_some(None);
    }
    // Each `[...]` item's range in `inner`, and whether `:` joins it to the
    // item before it as a column span.
    let mut items: Vec<(std::ops::Range<usize>, bool)> = Vec::new();
    let mut joined = false;
    let mut j = 0;
    while j < bytes.len() {
        match bytes[j] {
            b'[' => {
                let end = bracket_end(bytes, j);
                items.push((j..end, joined));
                joined = false;
                j = end;
            }
            b':' => {
                joined = true;
                j += 1;
            }
            b',' => {
                joined = false;
                j += 1;
            }
            _ => j += 1,
        }
    }
    let raw = |range: &std::ops::Range<usize>| {
        inner
            .get(range.start + 1..range.end.saturating_sub(1))
            .unwrap_or_default()
    };
    let position = |name: &str| {
        columns
            .iter()
            .position(|column| column.to_lowercase() == name.to_lowercase())
    };
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut k = 0;
    while k < items.len() {
        let first = &items[k].0;
        let name = unescape(raw(first));
        if let Some((second, true)) = items.get(k + 1) {
            let other = unescape(raw(second));
            if let (Some(a), Some(b)) = (position(&name), position(&other)) {
                let kept: Vec<&String> = columns[a.min(b)..=a.max(b)]
                    .iter()
                    .filter(|column| !gone.contains(&column.to_lowercase()))
                    .collect();
                let (Some(low), Some(high)) = (kept.first(), kept.last()) else {
                    return Some(None);
                };
                let (left, right) = if a <= b { (low, high) } else { (high, low) };
                if left.to_lowercase() != name.to_lowercase() {
                    edits.push((first.clone(), format!("[{}]", escape(left))));
                }
                if right.to_lowercase() != other.to_lowercase() {
                    edits.push((second.clone(), format!("[{}]", escape(right))));
                }
            }
            k += 2;
            continue;
        }
        if !raw(first).starts_with('#') && gone.contains(&name.to_lowercase()) {
            return Some(None);
        }
        k += 1;
    }
    if edits.is_empty() {
        return None;
    }
    let mut out = inner.to_owned();
    for (range, name) in edits.into_iter().rev() {
        out.replace_range(range, &name);
    }
    Some(Some(format!("[{out}]")))
}

/// Past the `]` closing the bracket that opens at `start`; a `'` escapes a
/// bracket, `#` or `'` after it.
fn bracket_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0;
    let mut i = start;
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
    i
}

/// Where the first unescaped `[` in `bytes` is.
fn bracket_at(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if matches!(bytes.get(i + 1), Some(b'[' | b']' | b'#' | b'\'')) => i += 2,
            b'[' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// A column name as a structured reference reads it, `'` escapes removed.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\''
            && let Some(&next) = chars.peek()
            && matches!(next, '[' | ']' | '#' | '\'')
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(ch);
    }
    out
}

/// A column name as a structured reference writes it.
fn escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if matches!(ch, '[' | ']' | '#' | '\'') {
            out.push('\'');
        }
        out.push(ch);
    }
    out
}
