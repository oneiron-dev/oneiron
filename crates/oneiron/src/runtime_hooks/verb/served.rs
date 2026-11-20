//! Served rows (ARCH-0080 §11 p15, the automation link): the rows a call
//! served its caller, read off the caller's view of its result. That is a
//! recall's pack, the cut pack a deadline returns included. The rows an
//! answer was only derived from are not served: a release judges those.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};

use crate::runtime_hooks::filter::glob_match;
use crate::{Error, Result};

/// The item fields [`rows`] reads.
const ROW_FIELDS: [&str; 6] = [
    "short_id",
    "source_revision_ref",
    "kind",
    "predicate",
    "world",
    "facet",
];

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

/// What [`rows`] reads of a view held as JSON text `text`, as a value no
/// deeper than a pack's rows: a `pack_version` (null) and, under `items`,
/// each item's string fields a served row takes, an item that is no object
/// as null. Every other member, of any depth, is passed over unread:
/// serde_json reads a raw member with no recursion. So a skill answer an
/// outer chain judges as text serves the rows its value would
/// (SKILL-ANSWER-DEEP-JSON-STACK-SAFE). `None` when the text is no object
/// with a `pack_version`, as [`rows`] reads no pack there.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when an object or string in it does not
/// read, which an admitted answer never makes: its every string reads as a
/// value's (`scalars_read_as_values`).
pub(super) fn text_pack(text: &RawValue) -> Result<Option<Value>> {
    let Some(members) = members_of(text.get())? else {
        return Ok(None);
    };
    if !members.contains_key("pack_version") {
        return Ok(None);
    }
    let mut pack = Map::new();
    pack.insert("pack_version".to_owned(), Value::Null);
    if let Some(items) = members.get("items")
        && items.get().trim_start().starts_with('[')
    {
        let items: Vec<&RawValue> = serde_json::from_str(items.get())
            .map_err(|_| Error::InvariantViolation("a served pack's items do not read"))?;
        let mut shown = Vec::with_capacity(items.len());
        for item in items {
            shown.push(match members_of(item.get())? {
                Some(fields) => Value::Object(row_fields(&fields)?),
                None => Value::Null,
            });
        }
        pack.insert("items".to_owned(), Value::Array(shown));
    }
    Ok(Some(Value::Object(pack)))
}

/// The members of JSON text `text`, each held as text, when it is an
/// object; a key given twice keeps its last value, as a value's map does.
fn members_of(text: &str) -> Result<Option<BTreeMap<String, &RawValue>>> {
    if !text.trim_start().starts_with('{') {
        return Ok(None);
    }
    serde_json::from_str(text)
        .map(Some)
        .map_err(|_| Error::InvariantViolation("an object held as text does not read"))
}

/// The [`ROW_FIELDS`] of item `fields` that hold strings, as strings.
fn row_fields(fields: &BTreeMap<String, &RawValue>) -> Result<Map<String, Value>> {
    let mut row = Map::new();
    for key in ROW_FIELDS {
        let Some(field) = fields.get(key) else {
            continue;
        };
        if field.get().trim_start().starts_with('"') {
            let text: String = serde_json::from_str(field.get())
                .map_err(|_| Error::InvariantViolation("a served row's field does not read"))?;
            row.insert(key.to_owned(), Value::String(text));
        }
    }
    Ok(row)
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
