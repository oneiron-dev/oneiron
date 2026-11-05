//! Core half of `serialize::json_format`: its store-layer items live in `oneiron_store::serialize::json_format` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::json_format::*;

use super::group_labels::group_key;
use super::pack_entry::PreparedEntity;
use super::types::GroupKey;
use serde_json::{Map, Number, Value};

pub(super) fn section_object(
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    include_score: bool,
    handles: &mut super::handles::Handles,
) -> Map<String, Value> {
    let mut map = Map::new();
    for (kind, entities) in groups {
        if entities.is_empty() {
            continue;
        }
        let mut rows = json_rows(entities, include_score);
        handles.emitted_rows(entities, &mut rows);
        map.insert(group_key(*kind).to_owned(), Value::Array(rows));
    }
    map
}
