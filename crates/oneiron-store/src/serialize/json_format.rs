//! JSON row and section shaping.

use serde_json::{Map, Number, Value};

use crate::serialize::group_labels::group_key;
use crate::serialize::pack_entry::PreparedEntity;
use crate::serialize::types::GroupKey;

pub fn json_rows(entities: &[PreparedEntity], include_score: bool) -> Vec<Value> {
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
