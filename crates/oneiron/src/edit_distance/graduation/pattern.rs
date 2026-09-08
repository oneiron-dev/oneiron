//! Scope-pattern syntax and axis matching for graduation thresholds.

use crate::consent_graduation::RampScope;

// ---------------------------------------------------------------------------
// Threshold rows
// ---------------------------------------------------------------------------

/// The pattern segment that matches any value on its axis.
pub(super) const PATTERN_WILDCARD: &str = "*";

/// The pattern axis separator.
const PATTERN_SEPARATOR: char = '/';

/// The character a lone [`PATTERN_WILDCARD`] axis is spelled with.
const PATTERN_WILDCARD_CHAR: char = '*';

/// Escapes the next character, so a pattern axis can spell a scope field that
/// contains a reserved one.
///
/// A [`RampScope`] field is arbitrary text — MS-06 trims it, rejects empty and
/// caps its length, and nothing more — so `op_kind = "send/email"` and
/// `target_class = "*"` are ordinary valid scopes. Without an escape,
/// [`exact_pattern`] would produce four axes for the first and a wildcard for
/// the second: a pattern that no row can be built from, and a pattern that
/// governs every scope on that axis. Either would make `exact_pattern` a lie
/// over part of the domain it accepts.
const PATTERN_ESCAPE: char = '\\';

/// Whether `ch` must be escaped to appear literally in a pattern axis.
const fn is_pattern_reserved(ch: char) -> bool {
    matches!(
        ch,
        PATTERN_ESCAPE | PATTERN_SEPARATOR | PATTERN_WILDCARD_CHAR
    )
}

/// The catch-all pattern: every scope matches it, which is what makes the
/// compiled table total.
pub const WILDCARD_PATTERN: &str = "*/*/*";

/// The three axes of a pattern — still escaped — or `None` when it is not
/// three well-formed non-empty ones.
///
/// Splits on UNESCAPED separators only, and rejects an escape that names
/// nothing or escapes an unreserved character. The second half is what keeps
/// the encoding canonical: one axis has exactly one spelling, so one pattern
/// has exactly one [`pattern_key`], and two rows can never mean the same thing
/// under two keys.
pub(super) fn pattern_axes(pattern: &str) -> Option<[&str; 3]> {
    let mut axes = [""; 3];
    let mut filled = 0;
    let mut start = 0;
    let mut escaped = false;
    for (idx, ch) in pattern.char_indices() {
        if escaped {
            if !is_pattern_reserved(ch) {
                return None;
            }
            escaped = false;
        } else if ch == PATTERN_ESCAPE {
            escaped = true;
        } else if ch == PATTERN_SEPARATOR {
            *axes.get_mut(filled)? = pattern.get(start..idx)?;
            filled += 1;
            start = idx + ch.len_utf8();
        }
    }
    if escaped {
        return None;
    }
    *axes.get_mut(filled)? = pattern.get(start..)?;
    if filled != 2 || axes.iter().any(|axis| axis.is_empty()) {
        return None;
    }
    Some(axes)
}

/// Whether one escaped pattern axis governs one scope field.
///
/// Compares against the unescaped axis without materializing it — the axis is
/// well-formed by [`pattern_axes`], so a walk in lockstep with the field is the
/// whole comparison.
pub(super) fn axis_matches(axis: &str, field: &str) -> bool {
    if axis == PATTERN_WILDCARD {
        return true;
    }
    let mut field = field.chars();
    let mut escaped = false;
    for ch in axis.chars() {
        if !escaped && ch == PATTERN_ESCAPE {
            escaped = true;
            continue;
        }
        escaped = false;
        if field.next() != Some(ch) {
            return false;
        }
    }
    field.next().is_none()
}

/// The pattern that names exactly one scope and nothing else — for every scope
/// [`RampScope::new`] accepts, reserved characters included.
#[must_use]
pub fn exact_pattern(scope: &RampScope) -> String {
    let mut pattern = String::new();
    for (index, field) in [&scope.op_kind, &scope.target_class, &scope.actor]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            pattern.push(PATTERN_SEPARATOR);
        }
        for ch in field.chars() {
            if is_pattern_reserved(ch) {
                pattern.push(PATTERN_ESCAPE);
            }
            pattern.push(ch);
        }
    }
    pattern
}
