//! Served rows (ARCH-0080 §11 p15, the automation link): the rows a call
//! served its caller, read off the caller's view of its result. That is a
//! recall's pack, the cut pack a deadline returns included. The rows an
//! answer was only derived from are not served: a release judges those.

use serde::Serialize;
use serde_json::Value;

use crate::runtime_hooks::filter::glob_match;

/// One served row, as a hook reads it.
#[derive(Debug, Serialize)]
pub(super) struct ServedRow<'v> {
    /// The short ref a hydrate takes.
    #[serde(rename = "ref")]
    reference: &'v str,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<&'v str>,
    kind: &'v str,
    #[serde(skip_serializing_if = "Option::is_none")]
    predicate: Option<&'v str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    world: Option<&'v str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facet: Option<&'v str>,
}

/// The rows `view` serves, in rank order, as `filter` takes them: every row
/// when it is empty. `None` when the view is no pack.
pub(super) fn rows<'v>(view: &'v Value, filter: &[String]) -> Option<Vec<ServedRow<'v>>> {
    view.get("pack_version")?;
    let items = view.get("items")?.as_array()?;
    let text = |item: &'v Value, key: &str| item.get(key).and_then(Value::as_str);
    Some(
        items
            .iter()
            .filter_map(|item| {
                Some(ServedRow {
                    reference: text(item, "short_id")?,
                    revision: text(item, "source_revision_ref"),
                    kind: text(item, "kind")?,
                    predicate: text(item, "predicate"),
                    world: text(item, "world"),
                    facet: text(item, "facet"),
                })
            })
            .filter(|row| filter.is_empty() || filter.iter().any(|entry| takes(entry, row)))
            .collect(),
    )
}

/// Whether a post-hook with served filter `filter` runs on `view`: always
/// without one; with one, when the view is a pack and a row it serves
/// matches.
pub(super) fn admits(filter: &[String], view: &Value) -> bool {
    filter.is_empty() || rows(view, filter).is_some_and(|rows| !rows.is_empty())
}

/// `<kind glob>:<predicate glob>`, where a row with no predicate matches
/// only `*`; or a bare predicate glob, over the rows that carry one (claims).
fn takes(entry: &str, row: &ServedRow<'_>) -> bool {
    match entry.split_once(':') {
        Some((kind, glob)) => {
            glob_match(kind, row.kind)
                && row
                    .predicate
                    .map_or(glob == "*", |predicate| glob_match(glob, predicate))
        }
        None => row
            .predicate
            .is_some_and(|predicate| glob_match(entry, predicate)),
    }
}
