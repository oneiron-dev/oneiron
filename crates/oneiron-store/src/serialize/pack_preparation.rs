//! Pack preparation: entity selection, field projection, value normalization,
//! and the per-format split of a pack into budgeted sections.

use std::collections::HashMap;

use serde_json::Value;

use crate::serialize::context_entity::ContextEntity;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::FieldProfile;
use crate::serialize::pack_format::PackFormat;
use oneiron_base::registry::ENTITY_TYPE_FEDERATION_GRANT;
use oneiron_base::tokenizer::PackTokenizer;
use oneiron_contracts::entity_id::EntityId;

use crate::serialize::field_profile_table::fields_for_profile;
use crate::serialize::token_budget::allocate_section_budgets;
use crate::serialize::types::TOON_MAX_DEPTH;
use crate::serialize::types::ValueDepthLimit;

pub fn value_depth_limit_for_format(format: PackFormat) -> ValueDepthLimit {
    if format == PackFormat::Toon {
        Some(TOON_MAX_DEPTH)
    } else {
        None
    }
}

pub fn should_include_projected_field(entity_type: u8, key: &str, value: &Value) -> bool {
    !(entity_type == ENTITY_TYPE_FEDERATION_GRANT && key == "member_ref" && value.is_null())
}

pub fn format_short_id(entity: &ContextEntity) -> String {
    let short_id = if entity.short_id.is_empty() {
        "unresolved".to_owned()
    } else {
        entity.short_id.clone()
    };

    let reference = format!("{}:{:02x}", short_id, entity.content_hash);
    match entity.source_revision_ref {
        Some(revision) => format!(
            "{reference}@{}",
            crate::revision_ref::RevisionRef(revision).to_hex()
        ),
        None => reference,
    }
}

pub fn field_keys(
    entity_type: u8,
    profile: FieldProfile,
    map: &HashMap<String, Value>,
) -> Vec<String> {
    let allow = fields_for_profile(entity_type, profile);
    if allow.is_empty() {
        let mut all: Vec<String> = map.keys().cloned().collect();
        all.sort();
        all
    } else {
        allow
            .iter()
            .filter_map(|key| map.get_key_value(*key).map(|(k, _)| k.clone()))
            .collect()
    }
}

pub fn normalize_value(
    key: &str,
    value: &Value,
    json_mode: bool,
    now: u64,
    max_field_chars: usize,
    value_depth_limit: ValueDepthLimit,
) -> Value {
    let mut value = if !json_mode && is_timestamp_field(key) {
        if let Some(ts) = value.as_u64() {
            Value::String(format_relative_timestamp(ts, now))
        } else if let Some(ts) = value.as_i64()
            && ts >= 0
        {
            Value::String(format_relative_timestamp(ts as u64, now))
        } else {
            clone_value_with_depth_limit(value, value_depth_limit)
        }
    } else {
        clone_value_with_depth_limit(value, value_depth_limit)
    };

    if max_field_chars > 0 {
        truncate_strings_with_depth_limit(&mut value, max_field_chars, value_depth_limit);
    }

    value
}

pub fn clone_value_with_depth_limit(value: &Value, value_depth_limit: ValueDepthLimit) -> Value {
    clone_value_at_depth(value, value_depth_limit, 0)
}

fn clone_value_at_depth(value: &Value, value_depth_limit: ValueDepthLimit, depth: usize) -> Value {
    if value_depth_limit_reached(value_depth_limit, depth) {
        return Value::Null;
    }

    match value {
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| clone_value_at_depth(value, value_depth_limit, depth + 1))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        clone_value_at_depth(value, value_depth_limit, depth + 1),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

pub fn is_timestamp_field(key: &str) -> bool {
    matches!(
        key,
        "at" | "from"
            | "to"
            | "start"
            | "end"
            | "occurred_start"
            | "occurred_end"
            | "learned_at"
            | "dueDate"
    )
}

pub fn truncate_strings_with_depth_limit(
    value: &mut Value,
    max_field_chars: usize,
    value_depth_limit: ValueDepthLimit,
) {
    truncate_strings_at_depth(value, max_field_chars, value_depth_limit, 0);
}

fn truncate_strings_at_depth(
    value: &mut Value,
    max_field_chars: usize,
    value_depth_limit: ValueDepthLimit,
    depth: usize,
) {
    if value_depth_limit_reached(value_depth_limit, depth) {
        return;
    }

    match value {
        Value::String(text) if text.chars().count() > max_field_chars => {
            let take = max_field_chars.saturating_sub(1);
            let truncated: String = text.chars().take(take).collect();
            *text = if take == 0 {
                "…".to_owned()
            } else {
                format!("{truncated}…")
            };
        }
        Value::String(_) => {}
        Value::Array(values) => {
            for value in values {
                truncate_strings_at_depth(value, max_field_chars, value_depth_limit, depth + 1);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                truncate_strings_at_depth(value, max_field_chars, value_depth_limit, depth + 1);
            }
        }
        _ => {}
    }
}

pub fn value_depth_limit_reached(value_depth_limit: ValueDepthLimit, depth: usize) -> bool {
    matches!(value_depth_limit, Some(limit) if depth >= limit)
}

fn format_relative_timestamp(ts: u64, now: u64) -> String {
    if ts == 0 {
        return String::new();
    }

    let (prefix, diff) = if ts > now {
        ("+", ts - now)
    } else {
        ("-", now - ts)
    };

    let minutes = diff / 60;
    let hours = diff / 3_600;
    let days = diff / 86_400;
    let weeks = days / 7;
    let months = days / 30;
    let years = days / 365;

    if minutes < 1 {
        "now".to_owned()
    } else if minutes < 60 {
        format!("{prefix}{minutes}m")
    } else if hours < 24 {
        format!("{prefix}{hours}h")
    } else if days < 7 {
        format!("{prefix}{days}d")
    } else if weeks < 5 {
        format!("{prefix}{weeks}w")
    } else if months < 12 {
        format!("{prefix}{months}mo")
    } else {
        format!("{prefix}{years}y")
    }
}
