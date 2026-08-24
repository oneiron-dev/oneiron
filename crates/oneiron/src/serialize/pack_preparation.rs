//! Pack preparation: entity selection, field projection, value normalization,
//! and the per-format split of a pack into budgeted sections.

use std::collections::HashMap;

use serde_json::Value;

use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::FieldProfile;
use crate::context_pack::PackFormat;
use crate::context_pack::PackStats;
use crate::context_pack::TokenAllocation;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::tokenizer::{DEFAULT_CONTEXT_PACK_TOKENIZER, PackTokenizer};

use super::field_profile_table::fields_for_profile;
use super::item_budget::apply_item_budget_with_depth_limit;
use super::pack_entry::{
    PreparedEntity, PreparedEntitySource, PreparedGroups, PreparedPack, SerializeConfig,
};
use super::token_budget::{
    allocate_section_budgets, budget_groups_with_depth_limit,
    enforce_token_budget_with_depth_limit, estimate_groups_tokens_with_depth_limit,
    finalize_pack_token_stats, group_entities, token_budget_droppable_count,
};
use super::types::{TOON_MAX_DEPTH, ValueDepthLimit};

pub(super) fn prepare_pack(
    pack: &ContextPack,
    config: &SerializeConfig,
    json_mode: bool,
) -> PreparedPack {
    let skip_budget = config.budget == 0;
    let value_depth_limit = value_depth_limit_for_format(config.format);
    let mut stats = pack.stats.clone();
    let tokenizer = DEFAULT_CONTEXT_PACK_TOKENIZER;

    let mut prepared = if config.merge_neighbors {
        let mut merged = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
        merged.extend(prepare_entities(
            &pack.results,
            PreparedEntitySource::Result,
            config,
            json_mode,
            value_depth_limit,
            &mut stats,
        ));
        merged.extend(prepare_entities(
            &pack.neighbors,
            PreparedEntitySource::Neighbor,
            config,
            json_mode,
            value_depth_limit,
            &mut stats,
        ));

        let mut groups = group_entities(merged);
        if !skip_budget {
            let before = token_budget_droppable_count(&groups);
            enforce_token_budget_with_depth_limit(
                &mut groups,
                &config.allocation,
                config.budget,
                tokenizer,
                value_depth_limit,
            );
            let after = token_budget_droppable_count(&groups);
            stats.items_dropped.count = stats
                .items_dropped
                .count
                .saturating_add(before.saturating_sub(after));
        }

        PreparedPack {
            merged: true,
            results: groups,
            neighbors: Vec::new(),
            stats,
        }
    } else {
        let results_source = group_entities(prepare_entities(
            &pack.results,
            PreparedEntitySource::Result,
            config,
            json_mode,
            value_depth_limit,
            &mut stats,
        ));
        let neighbors_source = group_entities(prepare_entities(
            &pack.neighbors,
            PreparedEntitySource::Neighbor,
            config,
            json_mode,
            value_depth_limit,
            &mut stats,
        ));
        let (results, neighbors) = if skip_budget {
            (results_source, neighbors_source)
        } else {
            let before = token_budget_droppable_count(&results_source)
                .saturating_add(token_budget_droppable_count(&neighbors_source));
            let sections = budget_split_sections_with_depth_limit(
                &results_source,
                &neighbors_source,
                &config.allocation,
                config.budget,
                tokenizer,
                value_depth_limit,
            );
            let after = token_budget_droppable_count(&sections.0)
                .saturating_add(token_budget_droppable_count(&sections.1));
            stats.items_dropped.count = stats
                .items_dropped
                .count
                .saturating_add(before.saturating_sub(after));
            sections
        };

        PreparedPack {
            merged: false,
            results,
            neighbors,
            stats,
        }
    };

    finalize_pack_token_stats(
        pack,
        config,
        &mut prepared,
        tokenizer,
        (!skip_budget).then_some(config.budget),
    );
    prepared
}

#[cfg(test)]
pub(super) fn budget_split_sections(
    results_source: &PreparedGroups,
    neighbors_source: &PreparedGroups,
    allocation: &TokenAllocation,
    token_budget: usize,
) -> (PreparedGroups, PreparedGroups) {
    budget_split_sections_with_depth_limit(
        results_source,
        neighbors_source,
        allocation,
        token_budget,
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    )
}

fn budget_split_sections_with_depth_limit(
    results_source: &PreparedGroups,
    neighbors_source: &PreparedGroups,
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> (PreparedGroups, PreparedGroups) {
    let results_need =
        estimate_groups_tokens_with_depth_limit(results_source, tokenizer, value_depth_limit);
    let neighbors_need =
        estimate_groups_tokens_with_depth_limit(neighbors_source, tokenizer, value_depth_limit);

    let section_budgets = allocate_section_budgets([results_need, neighbors_need], token_budget);
    let (mut results, results_used) = budget_groups_with_depth_limit(
        results_source,
        allocation,
        section_budgets[0],
        tokenizer,
        value_depth_limit,
    );
    let (mut neighbors, neighbors_used) = budget_groups_with_depth_limit(
        neighbors_source,
        allocation,
        section_budgets[1],
        tokenizer,
        value_depth_limit,
    );

    let leftover = token_budget.saturating_sub(results_used.saturating_add(neighbors_used));
    if leftover == 0 {
        return (results, neighbors);
    }

    let unmet = [
        results_need.saturating_sub(results_used),
        neighbors_need.saturating_sub(neighbors_used),
    ];
    if !unmet.iter().any(|need| *need > 0) {
        return (results, neighbors);
    }

    let extra = allocate_section_budgets(unmet, leftover);
    let final_budgets = [
        results_used.saturating_add(extra[0]),
        neighbors_used.saturating_add(extra[1]),
    ];
    debug_assert!(final_budgets[0].saturating_add(final_budgets[1]) <= token_budget);

    if final_budgets[0] > section_budgets[0] {
        results = budget_groups_with_depth_limit(
            results_source,
            allocation,
            final_budgets[0],
            tokenizer,
            value_depth_limit,
        )
        .0;
    }
    if final_budgets[1] > section_budgets[1] {
        neighbors = budget_groups_with_depth_limit(
            neighbors_source,
            allocation,
            final_budgets[1],
            tokenizer,
            value_depth_limit,
        )
        .0;
    }

    (results, neighbors)
}

fn value_depth_limit_for_format(format: PackFormat) -> ValueDepthLimit {
    if format == PackFormat::Toon {
        Some(TOON_MAX_DEPTH)
    } else {
        None
    }
}

fn prepare_entities(
    entities: &[ContextEntity],
    source: PreparedEntitySource,
    config: &SerializeConfig,
    json_mode: bool,
    value_depth_limit: ValueDepthLimit,
    stats: &mut PackStats,
) -> Vec<PreparedEntity> {
    let now = crate::unix_seconds_now();
    entities
        .iter()
        .filter_map(|entity| {
            let mut fields = Vec::new();

            if let Some(map) = entity.fields.as_ref() {
                let field_keys = field_keys(entity.entity_type, config.profile, map);
                for key in field_keys {
                    let Some(value) = map.get(&key) else {
                        continue;
                    };
                    if !should_include_projected_field(entity.entity_type, &key, value) {
                        continue;
                    }
                    let value = normalize_value(
                        &key,
                        value,
                        json_mode,
                        now,
                        config.max_field_chars,
                        value_depth_limit,
                    );
                    fields.push((key, value));
                }
            }

            let mut prepared = PreparedEntity {
                entity_type: entity.entity_type,
                score: entity.score,
                source,
                source_id: *entity.id.as_bytes(),
                id: format_short_id(entity),
                fields,
            };
            apply_item_budget_with_depth_limit(
                &mut prepared,
                config.max_item_tokens,
                stats,
                value_depth_limit,
            )
            .then_some(prepared)
        })
        .collect()
}

fn should_include_projected_field(entity_type: u8, key: &str, value: &Value) -> bool {
    !(entity_type == ENTITY_TYPE_FEDERATION_GRANT && key == "member_ref" && value.is_null())
}

fn format_short_id(entity: &ContextEntity) -> String {
    let short_id = if entity.short_id.is_empty() {
        entity.id.to_hex()
    } else {
        entity.short_id.clone()
    };

    format!("{}:{:02x}", short_id, entity.content_hash)
}

fn field_keys(entity_type: u8, profile: FieldProfile, map: &HashMap<String, Value>) -> Vec<String> {
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

fn normalize_value(
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

pub(super) fn clone_value_with_depth_limit(
    value: &Value,
    value_depth_limit: ValueDepthLimit,
) -> Value {
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

pub(super) fn is_timestamp_field(key: &str) -> bool {
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

pub(super) fn truncate_strings_with_depth_limit(
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

pub(super) fn value_depth_limit_reached(value_depth_limit: ValueDepthLimit, depth: usize) -> bool {
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
