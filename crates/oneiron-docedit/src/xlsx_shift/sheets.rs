//! Retargeting a formula's sheet prefixes when the workbook's sheets are
//! renamed or deleted, and writing a sheet name as a reference's prefix.

use super::{cell, number_end, quoted_end, token_end};

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
/// prefix changed. A reference into another workbook (`[1]Data!A1`) stays.
/// A 3D prefix that loses an end narrows to the first and last sheets it
/// keeps in `order`, the workbook's sheets before the change, as Excel's
/// does; it reads `#REF!` only when it keeps none.
#[must_use]
pub fn retarget_sheets(
    formula: &str,
    order: &[String],
    fate: &dyn Fn(&str) -> SheetFate,
) -> Option<String> {
    retarget_linked_sheets(formula, order, fate, &|_: &str| false)
}

/// [`retarget_sheets`], where a reference through a link `own` names by its
/// bracketed text (`1` of `[1]Data!A1`) is into this workbook itself and
/// follows `fate` as an unlinked one does: a renamed sheet keeps the link
/// (`[1]Sales!A1`), and a deleted one reads `#REF!` (FIX 9080).
#[must_use]
pub(crate) fn retarget_linked_sheets(
    formula: &str,
    order: &[String],
    fate: &dyn Fn(&str) -> SheetFate,
    own: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut changed = false;
    // The link a bracket just named, and where `out` holds it.
    let mut external: Option<(&str, usize)> = None;
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
            let link = formula[start..i]
                .strip_prefix('[')
                .and_then(|text| text.strip_suffix(']'))
                .unwrap_or_default();
            external = Some((link, out.len()));
            out.push_str(&formula[start..i]);
            // `[1]Data!` names a sheet of another workbook.
            continue;
        }
        let ch = formula[i..].chars().next()?;
        let (mut prefix, end) = if b == b'\'' {
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
                external = None;
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
                external = None;
                continue;
            }
            (formula[i..end].to_owned(), end)
        } else {
            out.push(ch);
            i += ch.len_utf8();
            external = None;
            continue;
        };
        let written = &formula[i..=end];
        i = end + 1;
        let mut link = std::mem::take(&mut external).map(|(link, at)| (link.to_owned(), at));
        // A quoted `'[1]My data'!` names its link inside the quotes.
        if link.is_none()
            && let Some((named, sheet)) = prefix
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
        {
            link = Some((named.to_owned(), out.len()));
            prefix = sheet.to_owned();
        }
        if link.as_ref().is_some_and(|(link, _)| !own(link)) || prefix.contains('[') {
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
        let names = match ends.as_slice() {
            [first, last] if fates.contains(&SheetFate::Delete) => {
                span_kept(first, last, order, fate)
            }
            _ if fates.contains(&SheetFate::Delete) => None,
            _ => Some(
                ends.iter()
                    .zip(&fates)
                    .map(|(name, fate)| match fate {
                        SheetFate::Rename(to) => to.clone(),
                        _ => (*name).to_owned(),
                    })
                    .collect(),
            ),
        };
        // The workbook's own link stays on a renamed sheet, inside the
        // quotes when its name needs them, and leaves with a deleted one.
        if let Some((_, at)) = &link {
            out.truncate(*at);
        }
        match names {
            Some(names) => {
                let sheet = sheet_prefix(&names.join(":"));
                match (&link, sheet.strip_prefix('\'')) {
                    (Some((link, _)), Some(quoted)) => out.push_str(&format!("'[{link}]{quoted}")),
                    (Some((link, _)), None) => out.push_str(&format!("[{link}]{sheet}")),
                    (None, _) => out.push_str(&sheet),
                }
                out.push('!');
            }
            None => out.push_str("#REF!"),
        }
    }
    changed.then_some(out)
}

/// The ends a 3D span `first:last` names once some of its sheets go: the
/// first and last sheets it keeps in workbook `order`, by the names `fate`
/// gives them, one name when it keeps one sheet. `None` when it keeps none
/// or an end is not in `order`.
fn span_kept(
    first: &str,
    last: &str,
    order: &[String],
    fate: &dyn Fn(&str) -> SheetFate,
) -> Option<Vec<String>> {
    let at = |name: &str| {
        order
            .iter()
            .position(|held| held.to_lowercase() == name.to_lowercase())
    };
    let (a, b) = (at(first)?, at(last)?);
    let kept: Vec<String> = order[a.min(b)..=a.max(b)]
        .iter()
        .filter_map(|name| match fate(name) {
            SheetFate::Keep => Some(name.clone()),
            SheetFate::Rename(to) => Some(to),
            SheetFate::Delete => None,
        })
        .collect();
    let (low, high) = (kept.first()?, kept.last()?);
    let (left, right) = if a <= b { (low, high) } else { (high, low) };
    Some(if left == right {
        vec![left.clone()]
    } else {
        vec![left.clone(), right.clone()]
    })
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
