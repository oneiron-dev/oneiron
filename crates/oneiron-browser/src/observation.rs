//! The observation contract both drivers answer (AB-001, AB-002).
//!
//! A row carries two names. Its `ref` is a live handle: a browser mints one
//! per DOM node of one document, from a counter the session never resets,
//! so a handle never names a node it did not name before. Its `locator` is
//! the semantic name built from its role, its accessible name and its named
//! ancestors, which a replay program stores and resolves on the page as it
//! is then. A desktop window has no live handles: its rows' `ref` is their
//! locator.
//!
//! An observation is whole, or an ordered edit of an earlier observation of
//! the same scope that the caller holds whole: `splice` names the base's
//! rows it replaces with `rows`. An act whose handle no longer stands acts
//! on the row its locator names now and says so, as `rebound`.

use crate::Row;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An observation a caller holds whole, which a later answer may edit: its
/// `scope` and `seq`, as that observation named them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationBase {
    pub scope: String,
    pub seq: u64,
}

/// One ordered edit of a base observation's rows: the `delete_count` rows
/// from `start` on give way to the answer's `rows`. The rows read now are
/// `base[..start] + rows + base[start + delete_count..]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RowSplice {
    pub start: u64,
    pub delete_count: u64,
}

/// How a target a call named resolved when no row carried it exactly: the
/// live handle `old` no longer stood (its node detached, was replaced, or
/// its document gave way), and the call took `new`, the row its `locator`
/// names now; or the locator `old` named several rows, and the call took
/// the first in the outline, as `ambiguous` and `candidates` say. The old
/// handle keeps naming its own node: it is never moved onto the new one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Rebound {
    /// The handle, or the locator, the call named.
    pub old: String,
    /// The handle of the row the call took.
    pub new: String,
    /// The scope the old handle was last read in; none for a locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_scope: Option<String>,
    pub new_scope: String,
    pub locator: String,
    /// More than one row carries the locator: the call took the first.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ambiguous: bool,
    /// The handles of every row the locator names, when ambiguous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

/// A batch step's target that resolved by its locator, by the step's index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StepRebound {
    pub step: usize,
    pub rebound: Rebound,
}

/// What a session knows of a live handle it minted: its row's locator, the
/// scope it was last read in, and the kind of secret its row showed then
/// (FIX 8028), when it showed one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleInfo {
    pub locator: String,
    pub scope: String,
    pub secret: Option<crate::SecretKind>,
}

/// Whether `target` has a live handle's form, `h<token>:<n>`. A locator
/// never does: a browser's starts `e`, a desktop's `d`.
#[must_use]
pub fn is_live_handle(target: &str) -> bool {
    target
        .strip_prefix('h')
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(token, n)| {
            !token.is_empty()
                && token.bytes().all(|b| b.is_ascii_hexdigit())
                && !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
        })
}

/// The row of `rows` that `target` names, by its index, and how it rebound:
/// the row carrying the live handle exactly; else, for a handle `known`
/// describes, the first row carrying its locator, rebound; else, for a
/// locator, the first row carrying it. Several rows with the locator mark
/// the choice ambiguous. None for an unknown handle, or no match.
pub(crate) fn match_target(
    target: &str,
    rows: &[Row],
    scope: &str,
    known: Option<&HandleInfo>,
) -> Option<(usize, Option<Rebound>)> {
    if let Some(at) = rows.iter().position(|row| row.target == target) {
        return Some((at, None));
    }
    let (locator, old_scope) = match known {
        Some(info) => (info.locator.as_str(), Some(info.scope.clone())),
        None if is_live_handle(target) => return None,
        None => (target, None),
    };
    let named: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.locator == locator)
        .map(|(at, _)| at)
        .collect();
    let first = *named.first()?;
    let ambiguous = named.len() > 1;
    let rebound = (known.is_some() || ambiguous).then(|| Rebound {
        old: target.to_owned(),
        new: rows[first].target.clone(),
        old_scope,
        new_scope: scope.to_owned(),
        locator: locator.to_owned(),
        ambiguous,
        candidates: if ambiguous {
            named.iter().map(|&at| rows[at].target.clone()).collect()
        } else {
            Vec::new()
        },
    });
    Some((first, rebound))
}

/// The rows of `rows` some target of `targets` names, in outline order, as
/// [`match_target`] matches each, and every rebinding the matches took.
/// `known` describes the live handles the session minted.
pub(crate) fn rows_named(
    targets: &[String],
    rows: &[Row],
    scope: &str,
    known: impl Fn(&str) -> Option<HandleInfo>,
) -> (Vec<Row>, Vec<Rebound>) {
    let mut keep = vec![false; rows.len()];
    let mut rebindings = Vec::new();
    for target in targets {
        let info = known(target);
        if let Some((at, rebound)) = match_target(target, rows, scope, info.as_ref()) {
            keep[at] = true;
            rebindings.extend(rebound);
        }
    }
    let named = rows
        .iter()
        .zip(keep)
        .filter(|(_, keep)| *keep)
        .map(|(row, _)| row.clone())
        .collect();
    (named, rebindings)
}

/// The ordered edit that makes `base` into `now`: the longest equal prefix
/// and then the longest equal suffix of what is left (whole-row equality)
/// stay, and the rows between are replaced. Rows that only moved change it.
#[cfg(feature = "driver")]
pub(crate) fn splice_of(base: &[Row], now: &[Row]) -> (RowSplice, Vec<Row>) {
    let prefix = base
        .iter()
        .zip(now)
        .take_while(|(was, is)| was == is)
        .count();
    let room = base.len().min(now.len()) - prefix;
    let suffix = base
        .iter()
        .rev()
        .zip(now.iter().rev())
        .take(room)
        .take_while(|(was, is)| was == is)
        .count();
    let splice = RowSplice {
        start: prefix as u64,
        delete_count: (base.len() - prefix - suffix) as u64,
    };
    (splice, now[prefix..now.len() - suffix].to_vec())
}
