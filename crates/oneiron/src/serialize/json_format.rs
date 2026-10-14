//! JSON row and section shaping.

use serde_json::{Map, Number, Value};

use super::group_labels::group_key;
use super::pack_entry::PreparedEntity;
use super::types::GroupKey;

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

pub(super) fn json_rows(entities: &[PreparedEntity], include_score: bool) -> Vec<Value> {
    entities
        .iter()
        .map(|entity| {
            let mut row = Map::new();
            row.insert("id".to_owned(), Value::String(entity.id.clone()));
            if include_score && let Some(score) = Number::from_f64(entity.score as f64) {
                row.insert("score".to_owned(), Value::Number(score));
            }
            for (key, value) in &entity.fields {
                row.insert(key.clone(), value.clone());
            }
            Value::Object(row)
        })
        .collect()
}
