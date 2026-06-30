use std::collections::{HashMap, HashSet};

use serde_json::{Map, Number, Value};

use crate::types::{
    ContextEntity, ContextPack, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SESSION,
    ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST,
    ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD, FieldProfile, PackFormat, PackStats, ResumeBundle, Signal,
    TokenAllocation,
};

const GROUP_ORDER: &[u8] = &[
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_EVENT,
    ENTITY_TYPE_PERSON,
    ENTITY_TYPE_SKILL,
    ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_PLACE,
];
// Use an impossible entity type as the shared sink for unknown groups.
const OTHER_ENTITY_TYPE: u8 = u8::MAX;
// Bound native TOON recursion for user/vault-provided JSON field values.
const TOON_MAX_DEPTH: usize = 128;
type ValueDepthLimit = Option<usize>;

/// Stable serializer identity recorded in whole-vault export manifests.
pub const WHOLE_VAULT_EXPORT_SERIALIZER: &str = "oneiron.whole_vault_export";
/// Version of the whole-vault export serializer contract.
pub const WHOLE_VAULT_EXPORT_SERIALIZER_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct SerializeConfig {
    pub format: PackFormat,
    pub profile: FieldProfile,
    pub budget: usize,
    pub allocation: TokenAllocation,
    pub include_stats: bool,
    pub merge_neighbors: bool,
    pub max_field_chars: usize,
    pub max_item_tokens: usize,
}

#[derive(Debug, Clone)]
struct PreparedEntity {
    entity_type: u8,
    score: f32,
    source: PreparedEntitySource,
    source_id: [u8; 16],
    id: String,
    fields: Vec<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedEntitySource {
    Result,
    Neighbor,
}

#[derive(Debug, Clone)]
struct PreparedPack {
    merged: bool,
    results: Vec<(u8, Vec<PreparedEntity>)>,
    neighbors: Vec<(u8, Vec<PreparedEntity>)>,
    stats: PackStats,
}

type PreparedGroups = Vec<(u8, Vec<PreparedEntity>)>;

#[derive(Debug, Clone)]
pub(crate) struct SerializedPackTelemetry {
    pub(crate) result_ids: Vec<[u8; 16]>,
    pub(crate) stats: PackStats,
}

pub fn serialize_pack(pack: &ContextPack, config: &SerializeConfig) -> Vec<u8> {
    let prepared = prepare_pack(pack, config, config.format == PackFormat::Json);
    serialize_prepared_pack(pack, config, prepared)
}

pub(crate) fn serialize_pack_with_telemetry(
    pack: &ContextPack,
    config: &SerializeConfig,
) -> (Vec<u8>, SerializedPackTelemetry) {
    let prepared = prepare_pack(pack, config, config.format == PackFormat::Json);
    let telemetry = serialize_prepared_pack_telemetry(&prepared);
    let bytes = serialize_prepared_pack(pack, config, prepared);
    (bytes, telemetry)
}

fn serialize_prepared_pack(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: PreparedPack,
) -> Vec<u8> {
    match config.format {
        PackFormat::Json => serialize_json(pack, config, prepared),
        PackFormat::Yaml => serialize_yaml(config, prepared).into_bytes(),
        PackFormat::Toon => serialize_toon(config, prepared).into_bytes(),
        PackFormat::Markdown => serialize_markdown(config, prepared).into_bytes(),
        PackFormat::Plaintext => serialize_plaintext(config, prepared).into_bytes(),
    }
}

fn serialize_prepared_pack_telemetry(prepared: &PreparedPack) -> SerializedPackTelemetry {
    let result_ids = prepared
        .results
        .iter()
        .flat_map(|(_, entities)| entities.iter())
        .filter(|entity| entity.source == PreparedEntitySource::Result)
        .map(|entity| entity.source_id)
        .collect();
    SerializedPackTelemetry {
        result_ids,
        stats: prepared.stats.clone(),
    }
}

pub fn serialize_resume_bundle(bundle: &ResumeBundle) -> Vec<u8> {
    serde_json::to_vec(bundle).expect("ResumeBundle JSON serialization should not fail")
}

fn serialize_json(pack: &ContextPack, config: &SerializeConfig, prepared: PreparedPack) -> Vec<u8> {
    let stats = prepared.stats.clone();
    let mut root = Map::new();

    if prepared.merged {
        for (kind, entities) in prepared.results {
            if entities.is_empty() {
                continue;
            }
            root.insert(
                group_key(kind).to_owned(),
                Value::Array(json_rows(&entities, true)),
            );
        }
    } else {
        root.insert(
            "results".to_owned(),
            Value::Object(section_object(&prepared.results, true)),
        );
        root.insert(
            "neighbors".to_owned(),
            Value::Object(section_object(&prepared.neighbors, true)),
        );
    }

    if config.include_stats {
        root.insert("stats".to_owned(), json_stats(&stats));
    }
    if let Some(empty) = &pack.empty
        && let Ok(value) = serde_json::to_value(empty)
    {
        root.insert("empty".to_owned(), value);
    }

    serde_json::to_vec(&Value::Object(root)).unwrap_or_else(|_| b"{}".to_vec())
}

fn serialize_toon(config: &SerializeConfig, prepared: PreparedPack) -> String {
    let mut out = String::new();
    if prepared.merged {
        out.push_str(&encode_toon_section(&prepared.results));
    } else {
        let results = encode_toon_section(&prepared.results);
        let neighbors = encode_toon_section(&prepared.neighbors);

        if !results.is_empty() {
            out.push_str(&results);
        }
        if !neighbors.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str("---neighbors\n");
            out.push_str(&neighbors);
        }
    }

    if config.include_stats {
        append_stats_line(&mut out, &prepared.stats, config.format);
    }

    out
}

fn serialize_markdown(config: &SerializeConfig, prepared: PreparedPack) -> String {
    let mut out = String::new();

    write_markdown_groups(&mut out, &prepared.results, "##");
    if !prepared.merged && !prepared.neighbors.is_empty() {
        if !out.is_empty() {
            out.push_str("\n---\n\n");
        }
        out.push_str("### Neighbors\n\n");
        write_markdown_groups(&mut out, &prepared.neighbors, "####");
    }

    if config.include_stats {
        append_stats_line(&mut out, &prepared.stats, config.format);
    }

    out
}

fn serialize_plaintext(config: &SerializeConfig, prepared: PreparedPack) -> String {
    let mut out = String::new();

    write_plaintext_groups(&mut out, &prepared.results);
    if !prepared.merged && !prepared.neighbors.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("---NEIGHBORS\n\n");
        write_plaintext_groups(&mut out, &prepared.neighbors);
    }

    if config.include_stats {
        append_stats_line(&mut out, &prepared.stats, config.format);
    }

    out
}

fn serialize_yaml(config: &SerializeConfig, prepared: PreparedPack) -> String {
    let mut out = String::new();

    if prepared.merged {
        write_yaml_groups(&mut out, &prepared.results, 0);
    } else {
        out.push_str("results:\n");
        write_yaml_groups(&mut out, &prepared.results, 2);
        out.push_str("# --- neighbors ---\n");
        out.push_str("neighbors:\n");
        write_yaml_groups(&mut out, &prepared.neighbors, 2);
    }

    if config.include_stats {
        append_stats_line(&mut out, &prepared.stats, config.format);
    }

    out
}

fn prepare_pack(pack: &ContextPack, config: &SerializeConfig, json_mode: bool) -> PreparedPack {
    let skip_budget = config.format == PackFormat::Json || config.budget == 0;
    let char_budget = config.budget.saturating_mul(4);
    let value_depth_limit = value_depth_limit_for_format(config.format);
    let mut stats = pack.stats.clone();

    if config.merge_neighbors {
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
                char_budget,
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
                char_budget,
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
    }
}

#[cfg(test)]
fn budget_split_sections(
    results_source: &PreparedGroups,
    neighbors_source: &PreparedGroups,
    allocation: &TokenAllocation,
    char_budget: usize,
) -> (PreparedGroups, PreparedGroups) {
    budget_split_sections_with_depth_limit(
        results_source,
        neighbors_source,
        allocation,
        char_budget,
        None,
    )
}

fn budget_split_sections_with_depth_limit(
    results_source: &PreparedGroups,
    neighbors_source: &PreparedGroups,
    allocation: &TokenAllocation,
    char_budget: usize,
    value_depth_limit: ValueDepthLimit,
) -> (PreparedGroups, PreparedGroups) {
    let results_need = estimate_groups_chars_with_depth_limit(results_source, value_depth_limit);
    let neighbors_need =
        estimate_groups_chars_with_depth_limit(neighbors_source, value_depth_limit);

    let section_budgets = allocate_section_budgets([results_need, neighbors_need], char_budget);
    let (mut results, results_used) = budget_groups_with_depth_limit(
        results_source,
        allocation,
        section_budgets[0],
        value_depth_limit,
    );
    let (mut neighbors, neighbors_used) = budget_groups_with_depth_limit(
        neighbors_source,
        allocation,
        section_budgets[1],
        value_depth_limit,
    );

    let leftover = char_budget.saturating_sub(results_used.saturating_add(neighbors_used));
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
    debug_assert!(final_budgets[0].saturating_add(final_budgets[1]) <= char_budget);

    if final_budgets[0] > section_budgets[0] {
        results = budget_groups_with_depth_limit(
            results_source,
            allocation,
            final_budgets[0],
            value_depth_limit,
        )
        .0;
    }
    if final_budgets[1] > section_budgets[1] {
        neighbors = budget_groups_with_depth_limit(
            neighbors_source,
            allocation,
            final_budgets[1],
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

#[cfg(test)]
fn apply_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    stats: &mut PackStats,
) -> bool {
    apply_item_budget_with_depth_limit(entity, max_item_tokens, stats, None)
}

fn apply_item_budget_with_depth_limit(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    stats: &mut PackStats,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    if max_item_tokens == 0 || is_critical_predicate_claim(entity) {
        return true;
    }

    let max_item_chars = max_item_tokens.saturating_mul(4);
    if max_item_chars == 0
        || estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars
    {
        return true;
    }

    let truncated = if entity.entity_type == ENTITY_TYPE_CLAIM {
        truncate_claim_value_for_item_budget(entity, max_item_chars, value_depth_limit)
    } else {
        truncate_non_claim_for_item_budget(entity, max_item_chars, value_depth_limit)
    };

    if estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars {
        if truncated {
            stats.items_truncated.count = stats.items_truncated.count.saturating_add(1);
        }
        true
    } else {
        stats.items_dropped.reason = crate::types::PackItemAccountingReason::ItemBudget;
        stats.items_dropped.count = stats.items_dropped.count.saturating_add(1);
        false
    }
}

fn truncate_non_claim_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_chars: usize,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let mut truncated = false;
    let mut tried_fields = Vec::new();

    while estimate_entity_chars_with_depth_limit(entity, value_depth_limit) > max_item_chars {
        let Some(field_index) =
            largest_truncatable_top_level_string_field(entity, tried_fields.as_slice())
        else {
            break;
        };

        tried_fields.push(field_index);
        truncated |= truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_chars,
            value_depth_limit,
        );
    }

    if estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars {
        return truncated;
    }

    truncated | retain_structural_item_budget_fields(entity)
}

fn truncate_claim_value_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_chars: usize,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let Some(value_index) = field_index(entity, "val") else {
        return retain_minimal_claim_item_budget_fields(entity, None);
    };

    let original_value = entity.fields[value_index].1.clone();
    let mut truncated = truncate_claim_value_field_for_item_budget(
        entity,
        value_index,
        max_item_chars,
        value_depth_limit,
    );

    if estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars {
        return truncated;
    }

    truncated |= retain_minimal_claim_item_budget_fields(entity, Some(original_value));
    if estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars {
        return truncated;
    }

    let Some(value_index) = field_index(entity, "val") else {
        return truncated;
    };
    truncated
        | truncate_claim_value_field_for_item_budget(
            entity,
            value_index,
            max_item_chars,
            value_depth_limit,
        )
}

fn truncate_claim_value_field_for_item_budget(
    entity: &mut PreparedEntity,
    field_index: usize,
    max_item_chars: usize,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let original_value_chars =
        estimate_value_chars_with_depth_limit(&entity.fields[field_index].1, value_depth_limit);

    match &mut entity.fields[field_index].1 {
        Value::String(_) => truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_chars,
            value_depth_limit,
        ),
        value => {
            *value = Value::String(truncation_suffix(original_value_chars));
            true
        }
    }
}

fn truncate_string_field_to_item_budget(
    entity: &mut PreparedEntity,
    field_index: usize,
    max_item_chars: usize,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let Value::String(original) = entity.fields[field_index].1.clone() else {
        return false;
    };

    let original_chars = original.chars().count();
    if original_chars == 0 {
        return false;
    }

    let suffix = truncation_suffix(original_chars);
    let mut low = 0_usize;
    let mut high = original_chars.saturating_sub(1);
    let mut best_prefix = None;

    while low <= high {
        let mid = low + ((high - low) / 2);
        entity.fields[field_index].1 =
            Value::String(truncate_with_suffix_prefix(&original, mid, &suffix));

        if estimate_entity_chars_with_depth_limit(entity, value_depth_limit) <= max_item_chars {
            best_prefix = Some(mid);
            low = mid.saturating_add(1);
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }

    let prefix_chars = best_prefix.unwrap_or(0);
    entity.fields[field_index].1 = Value::String(truncate_with_suffix_prefix(
        &original,
        prefix_chars,
        &suffix,
    ));
    true
}

fn retain_minimal_claim_item_budget_fields(
    entity: &mut PreparedEntity,
    original_value: Option<Value>,
) -> bool {
    let predicate = entity.fields.iter().find(|(key, _)| key == "pred").cloned();
    let value = original_value.map(|value| ("val".to_owned(), value));

    let mut minimal = Vec::new();
    if let Some(predicate) = predicate {
        minimal.push(predicate);
    }
    if let Some(value) = value {
        minimal.push(value);
    }

    let changed = entity.fields != minimal;
    entity.fields = minimal;
    changed
}

fn retain_structural_item_budget_fields(entity: &mut PreparedEntity) -> bool {
    let structural: Vec<(String, Value)> = entity
        .fields
        .iter()
        .filter(|(key, _)| is_structural_item_budget_field(key))
        .cloned()
        .collect();
    let changed = entity.fields != structural;
    entity.fields = structural;
    changed
}

fn is_structural_item_budget_field(key: &str) -> bool {
    key == "pred"
}

fn field_index(entity: &PreparedEntity, key: &str) -> Option<usize> {
    entity
        .fields
        .iter()
        .position(|(field_key, _)| field_key == key)
}

fn largest_truncatable_top_level_string_field(
    entity: &PreparedEntity,
    excluded: &[usize],
) -> Option<usize> {
    entity
        .fields
        .iter()
        .enumerate()
        .filter_map(|(index, (key, value))| {
            if excluded.contains(&index) || is_structural_item_budget_field(key) {
                return None;
            }

            let Value::String(text) = value else {
                return None;
            };
            Some((index, text.chars().count()))
        })
        .max_by_key(|(_, chars)| *chars)
        .map(|(index, _)| index)
}

fn truncate_with_suffix_prefix(text: &str, prefix_chars: usize, suffix: &str) -> String {
    let prefix: String = text.chars().take(prefix_chars).collect();
    format!("{prefix}{suffix}")
}

fn truncation_suffix(original_chars: usize) -> String {
    format!("...(truncated, {original_chars} chars total)")
}

fn is_critical_predicate_claim(entity: &PreparedEntity) -> bool {
    if entity.entity_type != ENTITY_TYPE_CLAIM {
        return false;
    }

    let Some(predicate) = entity
        .fields
        .iter()
        .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten())
    else {
        return false;
    };

    predicate == "commitment.promise"
        || predicate.starts_with("profile.")
        || predicate.starts_with("preference.")
        || predicate.starts_with("companion.")
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

fn clone_value_with_depth_limit(value: &Value, value_depth_limit: ValueDepthLimit) -> Value {
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

fn is_timestamp_field(key: &str) -> bool {
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

fn truncate_strings_with_depth_limit(
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

fn value_depth_limit_reached(value_depth_limit: ValueDepthLimit, depth: usize) -> bool {
    matches!(value_depth_limit, Some(limit) if depth >= limit)
}

fn group_entities(entities: Vec<PreparedEntity>) -> Vec<(u8, Vec<PreparedEntity>)> {
    let mut buckets = HashMap::<u8, Vec<PreparedEntity>>::new();
    for mut entity in entities {
        entity.entity_type = normalize_group_entity_type(entity.entity_type);
        buckets.entry(entity.entity_type).or_default().push(entity);
    }

    for rows in buckets.values_mut() {
        rows.sort_unstable_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    }

    let mut out = Vec::new();
    for entity_type in GROUP_ORDER {
        if let Some(rows) = buckets.remove(entity_type)
            && !rows.is_empty()
        {
            out.push((*entity_type, rows));
        }
    }

    let mut rest: Vec<(u8, Vec<PreparedEntity>)> = buckets.into_iter().collect();
    rest.sort_unstable_by_key(|(entity_type, _)| *entity_type);
    for (entity_type, rows) in rest {
        if !rows.is_empty() {
            out.push((entity_type, rows));
        }
    }

    out
}

fn token_budget_droppable_count(groups: &[(u8, Vec<PreparedEntity>)]) -> usize {
    groups
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .filter(|row| !is_critical_predicate_claim(row))
        .count()
}

fn type_fraction(entity_type: u8, allocation: &TokenAllocation) -> f32 {
    match entity_type {
        0 => allocation.claims,
        1 => allocation.turns,
        8 => allocation.summaries,
        _ => allocation.other,
    }
}

fn enforce_token_budget_with_depth_limit(
    groups: &mut Vec<(u8, Vec<PreparedEntity>)>,
    allocation: &TokenAllocation,
    char_budget: usize,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    if char_budget == 0 {
        let mut total_used = 0_usize;
        for (_, rows) in groups.iter_mut() {
            let mut used = 0_usize;
            rows.retain(|row| {
                let keep = is_critical_predicate_claim(row);
                if keep {
                    used = used.saturating_add(estimate_entity_chars_with_depth_limit(
                        row,
                        value_depth_limit,
                    ));
                }
                keep
            });
            total_used = total_used.saturating_add(used);
        }
        groups.retain(|(_, rows)| !rows.is_empty());
        return total_used;
    }

    // Normalize fractions so they sum to 1.0 (multiple "other" types each
    // get allocation.other, so raw sum can exceed 1.0).
    let raw: Vec<f32> = groups
        .iter()
        .map(|(et, _)| type_fraction(*et, allocation))
        .collect();
    let total: f32 = raw.iter().sum();
    let norm = if total > 0.0 { 1.0 / total } else { 0.0 };

    // First pass: compute initial budgets vs actual needs.
    let mut budgets: Vec<usize> = Vec::with_capacity(groups.len());
    let mut needs: Vec<usize> = Vec::with_capacity(groups.len());
    let mut surplus: usize = 0;
    let mut hungry_weight: f32 = 0.0;

    for (i, (_, rows)) in groups.iter().enumerate() {
        let frac = raw[i] * norm;
        let budget = (char_budget as f32 * frac) as usize;
        let needed: usize = rows
            .iter()
            .map(|row| estimate_entity_chars_with_depth_limit(row, value_depth_limit))
            .sum();
        if needed <= budget {
            surplus += budget - needed;
        } else {
            hungry_weight += frac;
        }
        budgets.push(budget);
        needs.push(needed);
    }

    // Second pass: redistribute surplus to hungry types, then truncate.
    let mut total_used = 0_usize;
    for (i, (_, rows)) in groups.iter_mut().enumerate() {
        let final_budget = if needs[i] <= budgets[i] {
            // Satisfied — cap at what it needs, release rest.
            needs[i]
        } else if hungry_weight > 0.0 {
            let frac = raw[i] * norm;
            let extra = (surplus as f32 * (frac / hungry_weight)) as usize;
            budgets[i] + extra
        } else {
            budgets[i]
        };

        let mut used = 0_usize;
        let mut kept = Vec::with_capacity(rows.len());
        let mut kept_noncritical = 0_usize;
        let mut noncritical_closed = final_budget == 0;
        for row in rows.drain(..) {
            let chars = estimate_entity_chars_with_depth_limit(&row, value_depth_limit);
            if is_critical_predicate_claim(&row) {
                used = used.saturating_add(chars);
                kept.push(row);
                continue;
            }
            if noncritical_closed {
                continue;
            }
            if used.saturating_add(chars) > final_budget && kept_noncritical > 0 {
                noncritical_closed = true;
                continue;
            }
            kept_noncritical += 1;
            used = used.saturating_add(chars);
            kept.push(row);
        }
        *rows = kept;
        total_used = total_used.saturating_add(used);
    }

    groups.retain(|(_, rows)| !rows.is_empty());
    total_used
}

#[cfg(test)]
fn estimate_entity_chars(entity: &PreparedEntity) -> usize {
    estimate_entity_chars_with_depth_limit(entity, None)
}

fn estimate_entity_chars_with_depth_limit(
    entity: &PreparedEntity,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    let mut chars = entity.id.len() + 12;
    for (key, value) in &entity.fields {
        chars += estimate_json_string_chars(key);
        chars += estimate_value_chars_with_depth_limit(value, value_depth_limit);
        chars += 2;
    }
    chars
}

#[cfg(test)]
fn estimate_groups_chars(groups: &[(u8, Vec<PreparedEntity>)]) -> usize {
    estimate_groups_chars_with_depth_limit(groups, None)
}

fn estimate_groups_chars_with_depth_limit(
    groups: &[(u8, Vec<PreparedEntity>)],
    value_depth_limit: ValueDepthLimit,
) -> usize {
    groups
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .map(|entity| estimate_entity_chars_with_depth_limit(entity, value_depth_limit))
        .sum()
}

#[cfg(test)]
fn budget_groups(
    source: &[(u8, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    char_budget: usize,
) -> (Vec<(u8, Vec<PreparedEntity>)>, usize) {
    budget_groups_with_depth_limit(source, allocation, char_budget, None)
}

fn budget_groups_with_depth_limit(
    source: &[(u8, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    char_budget: usize,
    value_depth_limit: ValueDepthLimit,
) -> (Vec<(u8, Vec<PreparedEntity>)>, usize) {
    let mut groups = source.to_vec();
    let used = enforce_token_budget_with_depth_limit(
        &mut groups,
        allocation,
        char_budget,
        value_depth_limit,
    );
    (groups, used)
}

fn allocate_section_budgets(needs: [usize; 2], total_budget: usize) -> [usize; 2] {
    if total_budget == 0 {
        return [0, 0];
    }

    let total_need = needs[0].saturating_add(needs[1]);
    if total_need <= total_budget {
        return needs;
    }
    debug_assert!(total_need > 0);

    let total_budget = total_budget as u128;
    let total_need = total_need as u128;
    let mut budgets = [0_usize, 0_usize];
    let mut remainders = [(0_usize, 0_u128), (1_usize, 0_u128)];
    let mut allocated = 0_usize;

    for (index, need) in needs.into_iter().enumerate() {
        let product = total_budget.saturating_mul(need as u128);
        budgets[index] = (product / total_need) as usize;
        remainders[index] = (index, product % total_need);
        allocated = allocated.saturating_add(budgets[index]);
    }

    let mut leftover = (total_budget as usize).saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        budgets[index] = budgets[index].saturating_add(1);
        leftover -= 1;
    }

    budgets
}

fn section_object(groups: &[(u8, Vec<PreparedEntity>)], include_score: bool) -> Map<String, Value> {
    let mut map = Map::new();
    for (kind, entities) in groups {
        if entities.is_empty() {
            continue;
        }
        map.insert(
            group_key(*kind).to_owned(),
            Value::Array(json_rows(entities, include_score)),
        );
    }
    map
}

fn json_rows(entities: &[PreparedEntity], include_score: bool) -> Vec<Value> {
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

fn encode_toon_section(groups: &[(u8, Vec<PreparedEntity>)]) -> String {
    if groups.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    write_toon_object(&mut out, &section_object(groups, false), 0);
    out
}

fn write_toon_object(out: &mut String, object: &Map<String, Value>, depth: usize) {
    if toon_depth_limit_reached(depth) {
        write_toon_depth_limit_value(out);
        return;
    }

    for (index, (key, value)) in object.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }

        match value {
            Value::Array(values) => write_toon_array(out, Some(key), values, depth),
            Value::Object(nested) => {
                if !nested.is_empty() && toon_depth_limit_reached(depth + 1) {
                    write_toon_keyed_depth_limit_value(out, key, depth);
                } else {
                    write_indent(out, depth * 2);
                    write_toon_key(out, key);
                    out.push(':');
                }
                if !nested.is_empty() && !toon_depth_limit_reached(depth + 1) {
                    out.push('\n');
                    write_toon_object(out, nested, depth + 1);
                }
            }
            _ => {
                write_indent(out, depth * 2);
                write_toon_key(out, key);
                out.push_str(": ");
                write_toon_primitive(out, value);
            }
        }
    }
}

fn write_toon_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    if toon_depth_limit_reached(depth) {
        write_toon_array_depth_limit_value(out, key, depth);
        return;
    }

    if values.is_empty() {
        write_toon_array_header(out, key, 0, None, depth);
        return;
    }

    if let Some(fields) = toon_tabular_fields(values) {
        write_toon_tabular_array(out, key, values, &fields, depth);
    } else if values.iter().all(is_toon_primitive) {
        write_toon_primitive_array(out, key, values, depth);
    } else {
        write_toon_nested_array(out, key, values, depth);
    }
}

fn write_toon_array_header(
    out: &mut String,
    key: Option<&str>,
    length: usize,
    fields: Option<&[String]>,
    depth: usize,
) {
    if let Some(key) = key {
        write_indent(out, depth * 2);
        write_toon_key(out, key);
    }

    out.push('[');
    out.push_str(&length.to_string());
    out.push(']');

    if let Some(fields) = fields {
        out.push('{');
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_toon_key(out, field);
        }
        out.push('}');
    }

    out.push(':');
}

fn write_toon_primitive_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    write_toon_array_header(out, key, values.len(), None, depth);
    out.push(' ');

    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_toon_primitive(out, value);
    }
}

fn write_toon_tabular_array(
    out: &mut String,
    key: Option<&str>,
    values: &[Value],
    fields: &[String],
    depth: usize,
) {
    write_toon_array_header(out, key, values.len(), Some(fields), depth);
    out.push('\n');

    for (row_index, value) in values.iter().enumerate() {
        let Some(row) = value.as_object() else {
            continue;
        };

        write_indent(out, (depth + 1) * 2);
        for (field_index, field) in fields.iter().enumerate() {
            if field_index > 0 {
                out.push(',');
            }

            if let Some(value) = row.get(field) {
                write_toon_primitive(out, value);
            } else {
                out.push_str("null");
            }
        }

        if row_index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn write_toon_nested_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    write_toon_array_header(out, key, values.len(), None, depth);
    out.push('\n');

    for (index, value) in values.iter().enumerate() {
        write_indent(out, (depth + 1) * 2);
        out.push('-');

        match value {
            Value::Array(values) => {
                out.push(' ');
                write_toon_array(out, None, values, depth + 1);
            }
            Value::Object(object) => write_toon_list_item_object(out, object, depth + 1),
            _ => {
                out.push(' ');
                write_toon_primitive(out, value);
            }
        }

        if index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn write_toon_list_item_object(out: &mut String, object: &Map<String, Value>, depth: usize) {
    if !object.is_empty() && toon_depth_limit_reached(depth) {
        out.push(' ');
        write_toon_depth_limit_value(out);
        return;
    }

    let mut fields = object.iter();
    let Some((first_key, first_value)) = fields.next() else {
        return;
    };

    out.push(' ');
    write_toon_list_item_field(out, first_key, first_value, depth, true);

    for (key, value) in fields {
        out.push('\n');
        write_indent(out, (depth + 1) * 2);
        write_toon_list_item_field(out, key, value, depth, false);
    }
}

fn write_toon_list_item_field(
    out: &mut String,
    key: &str,
    value: &Value,
    depth: usize,
    first_field: bool,
) {
    match value {
        Value::Array(values) => {
            write_toon_key(out, key);
            if toon_depth_limit_reached(depth + 1) {
                out.push_str(": ");
                write_toon_depth_limit_value(out);
            } else if first_field && let Some(fields) = toon_tabular_fields(values) {
                write_toon_list_item_tabular_array(out, values, &fields, depth);
            } else {
                write_toon_array(out, None, values, depth + 1);
            }
        }
        Value::Object(object) => {
            write_toon_key(out, key);
            out.push(':');
            if !object.is_empty() {
                if toon_depth_limit_reached(depth + 2) {
                    out.push(' ');
                    write_toon_depth_limit_value(out);
                } else {
                    out.push('\n');
                    write_toon_object(out, object, depth + 2);
                }
            }
        }
        _ => {
            write_toon_key(out, key);
            out.push_str(": ");
            write_toon_primitive(out, value);
        }
    }
}

fn write_toon_list_item_tabular_array(
    out: &mut String,
    values: &[Value],
    fields: &[String],
    depth: usize,
) {
    out.push('[');
    out.push_str(&values.len().to_string());
    out.push_str("]{");
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_toon_key(out, field);
    }
    out.push_str("}:\n");

    for (row_index, value) in values.iter().enumerate() {
        let Some(row) = value.as_object() else {
            continue;
        };

        write_indent(out, (depth + 2) * 2);
        for (field_index, field) in fields.iter().enumerate() {
            if field_index > 0 {
                out.push(',');
            }

            if let Some(value) = row.get(field) {
                write_toon_primitive(out, value);
            } else {
                out.push_str("null");
            }
        }

        if row_index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn toon_tabular_fields(values: &[Value]) -> Option<Vec<String>> {
    let first = values.first()?.as_object()?;
    if first.is_empty() {
        return None;
    }
    if first.values().any(|value| !is_toon_primitive(value)) {
        return None;
    }

    let fields: Vec<String> = first.keys().cloned().collect();
    for value in values.iter().skip(1) {
        let row = value.as_object()?;
        if row.len() != fields.len()
            || fields.iter().any(|field| !row.contains_key(field))
            || row.values().any(|value| !is_toon_primitive(value))
        {
            return None;
        }
    }

    Some(fields)
}

fn toon_depth_limit_reached(depth: usize) -> bool {
    depth >= TOON_MAX_DEPTH
}

fn write_toon_depth_limit_value(out: &mut String) {
    out.push_str("null");
}

fn write_toon_keyed_depth_limit_value(out: &mut String, key: &str, depth: usize) {
    write_indent(out, depth * 2);
    write_toon_key(out, key);
    out.push_str(": ");
    write_toon_depth_limit_value(out);
}

fn write_toon_array_depth_limit_value(out: &mut String, key: Option<&str>, depth: usize) {
    if let Some(key) = key {
        write_toon_keyed_depth_limit_value(out, key, depth);
    } else {
        write_toon_depth_limit_value(out);
    }
}

fn is_toon_primitive(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn write_toon_primitive(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&format_toon_number(value)),
        Value::String(value) => write_toon_string(out, value),
        Value::Array(_) | Value::Object(_) => {}
    }
}

fn format_toon_number(number: &Number) -> String {
    if let Some(value) = number.as_i64() {
        return value.to_string();
    }
    if let Some(value) = number.as_u64() {
        return value.to_string();
    }
    if let Some(value) = number.as_f64() {
        return format_toon_float(value);
    }
    number.to_string()
}

fn format_toon_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() <= i64::MAX as f64 {
        return (value as i64).to_string();
    }

    let formatted = value.to_string();
    if formatted.contains('e') || formatted.contains('E') {
        format_toon_float_without_exponent(value)
    } else {
        trim_toon_float_zeros(&formatted)
    }
}

fn format_toon_float_without_exponent(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_owned();
    }

    if value.abs() >= 1.0 {
        let abs_value = value.abs();
        let integer = abs_value.trunc();
        let fraction = abs_value.fract();
        if fraction == 0.0 {
            format!("{}{}", if value < 0.0 { "-" } else { "" }, integer as i64)
        } else {
            trim_toon_float_zeros(&format!("{value:.17}"))
        }
    } else if value == 0.0 {
        "0".to_owned()
    } else {
        trim_toon_float_zeros(&format!("{value:.17}"))
    }
}

fn trim_toon_float_zeros(value: &str) -> String {
    let Some((integer, fraction)) = value.split_once('.') else {
        return value.to_owned();
    };

    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.to_owned()
    } else {
        format!("{integer}.{fraction}")
    }
}

fn write_toon_key(out: &mut String, value: &str) {
    if is_valid_unquoted_toon_key(value) {
        out.push_str(value);
    } else {
        write_quoted_toon_string(out, value);
    }
}

fn write_toon_string(out: &mut String, value: &str) {
    if needs_quoted_toon_string(value) {
        write_quoted_toon_string(out, value);
    } else {
        out.push_str(value);
    }
}

fn write_quoted_toon_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn is_valid_unquoted_toon_key(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };

    (first.is_alphabetic() || first == '_')
        && value
            .chars()
            .skip(1)
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '.')
}

fn needs_quoted_toon_string(value: &str) -> bool {
    if value.is_empty() || matches!(value, "null" | "true" | "false") {
        return true;
    }

    if is_numeric_like_toon_string(value)
        || value.chars().any(is_toon_structural_char)
        || value
            .chars()
            .any(|ch| matches!(ch, ',' | '\\' | '"' | '\n' | '\r' | '\t'))
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.starts_with('-')
    {
        return true;
    }

    value.starts_with('0')
        && value.len() > 1
        && value.chars().nth(1).is_some_and(|ch| ch.is_ascii_digit())
}

fn is_numeric_like_toon_string(value: &str) -> bool {
    let mut chars = value.chars();
    let first = match chars.next() {
        Some('-') => match chars.next() {
            Some(ch) => ch,
            None => return false,
        },
        Some(ch) => ch,
        None => return false,
    };

    if !first.is_ascii_digit() {
        return false;
    }
    if first == '0' && chars.clone().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return false;
    }

    chars.all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | 'e' | 'E' | '+' | '-'))
}

fn is_toon_structural_char(value: char) -> bool {
    matches!(value, '[' | ']' | '{' | '}' | ':' | '-')
}

fn write_markdown_groups(out: &mut String, groups: &[(u8, Vec<PreparedEntity>)], level: &str) {
    let mut first_group = true;
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        if !first_group {
            out.push('\n');
        }
        first_group = false;

        out.push_str(level);
        out.push(' ');
        out.push_str(group_title(*entity_type));
        out.push_str("\n\n");

        let columns = collect_columns(rows);
        if columns.is_empty() {
            continue;
        }

        out.push('|');
        for col in &columns {
            out.push(' ');
            out.push_str(col);
            out.push(' ');
            out.push('|');
        }
        out.push('\n');

        out.push('|');
        for _ in &columns {
            out.push_str("----|");
        }
        out.push('\n');

        for row in rows {
            out.push('|');
            for col in &columns {
                let value = markdown_value_for_column(row, col);
                out.push(' ');
                out.push_str(&escape_markdown(&value));
                out.push(' ');
                out.push('|');
            }
            out.push('\n');
        }
    }
}

fn markdown_value_for_column(entity: &PreparedEntity, column: &str) -> String {
    if column == "id" {
        return entity.id.clone();
    }

    for (key, value) in &entity.fields {
        if key == column {
            return value_to_text(value, true);
        }
    }

    String::new()
}

fn write_plaintext_groups(out: &mut String, groups: &[(u8, Vec<PreparedEntity>)]) {
    let mut first_group = true;
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        if !first_group {
            out.push('\n');
        }
        first_group = false;

        out.push_str(group_name(*entity_type));
        out.push('\n');

        let columns = collect_columns(rows);
        for row in rows {
            let mut first_col = true;
            for col in &columns {
                if !first_col {
                    out.push('|');
                }
                first_col = false;

                let value = if col == "id" {
                    row.id.clone()
                } else {
                    row.fields
                        .iter()
                        .find(|(key, _)| key == col)
                        .map(|(_, value)| value_to_text(value, false))
                        .unwrap_or_default()
                };
                out.push_str(&escape_plaintext(&value));
            }
            out.push('\n');
        }
    }
}

fn write_yaml_groups(out: &mut String, groups: &[(u8, Vec<PreparedEntity>)], indent: usize) {
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        write_indent(out, indent);
        out.push_str(group_key(*entity_type));
        out.push_str(":\n");

        for row in rows {
            write_indent(out, indent + 2);
            out.push_str("- id: ");
            out.push_str(&yaml_scalar(&Value::String(row.id.clone())));
            out.push('\n');

            for (key, value) in &row.fields {
                write_indent(out, indent + 4);
                out.push_str(&yaml_key(key));
                out.push_str(": ");
                out.push_str(&yaml_scalar(value));
                out.push('\n');
            }
        }
    }
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push(' ');
    }
}

fn collect_columns(rows: &[PreparedEntity]) -> Vec<String> {
    let id_col = "id".to_owned();
    let mut seen = HashSet::<String>::new();
    seen.insert(id_col.clone());
    let mut columns = vec![id_col];

    for row in rows {
        for (key, _) in &row.fields {
            if seen.insert(key.clone()) {
                columns.push(key.clone());
            }
        }
    }

    columns
}

#[derive(Clone, Copy)]
struct GroupLabels {
    key: &'static str,
    name: &'static str,
    title: &'static str,
}

const OTHER_GROUP_LABELS: GroupLabels = GroupLabels {
    key: "other",
    name: "OTHER",
    title: "Other",
};

fn group_labels(entity_type: u8) -> GroupLabels {
    known_group_labels(entity_type).unwrap_or(OTHER_GROUP_LABELS)
}

fn known_group_labels(entity_type: u8) -> Option<GroupLabels> {
    match entity_type {
        ENTITY_TYPE_CLAIM => Some(GroupLabels {
            key: "claims",
            name: "CLAIMS",
            title: "Claims",
        }),
        ENTITY_TYPE_TURN => Some(GroupLabels {
            key: "turns",
            name: "TURNS",
            title: "Turns",
        }),
        ENTITY_TYPE_SESSION => Some(GroupLabels {
            key: "sessions",
            name: "SESSIONS",
            title: "Sessions",
        }),
        ENTITY_TYPE_MESSAGE => Some(GroupLabels {
            key: "messages",
            name: "MESSAGES",
            title: "Messages",
        }),
        ENTITY_TYPE_PERSON => Some(GroupLabels {
            key: "persons",
            name: "PERSONS",
            title: "Persons",
        }),
        ENTITY_TYPE_RELATIONSHIP => Some(GroupLabels {
            key: "relationships",
            name: "RELATIONSHIPS",
            title: "Relationships",
        }),
        ENTITY_TYPE_EVENT => Some(GroupLabels {
            key: "events",
            name: "EVENTS",
            title: "Events",
        }),
        ENTITY_TYPE_SKILL => Some(GroupLabels {
            key: "skills",
            name: "SKILLS",
            title: "Skills",
        }),
        ENTITY_TYPE_SUMMARY => Some(GroupLabels {
            key: "summaries",
            name: "SUMMARIES",
            title: "Summaries",
        }),
        ENTITY_TYPE_PLACE => Some(GroupLabels {
            key: "places",
            name: "PLACES",
            title: "Places",
        }),
        ENTITY_TYPE_ASSET_TEXT => Some(GroupLabels {
            key: "texts",
            name: "TEXTS",
            title: "Texts",
        }),
        ENTITY_TYPE_CONVERSATION => Some(GroupLabels {
            key: "conversations",
            name: "CONVERSATIONS",
            title: "Conversations",
        }),
        ENTITY_TYPE_ORG => Some(GroupLabels {
            key: "organizations",
            name: "ORGANIZATIONS",
            title: "Organizations",
        }),
        ENTITY_TYPE_FACET => Some(GroupLabels {
            key: "facets",
            name: "FACETS",
            title: "Facets",
        }),
        ENTITY_TYPE_WORLD => Some(GroupLabels {
            key: "worlds",
            name: "WORLDS",
            title: "Worlds",
        }),
        ENTITY_TYPE_ASSET => Some(GroupLabels {
            key: "assets",
            name: "ASSETS",
            title: "Assets",
        }),
        ENTITY_TYPE_NOTIFICATION => Some(GroupLabels {
            key: "notifications",
            name: "NOTIFICATIONS",
            title: "Notifications",
        }),
        // Productivity (80-99)
        ENTITY_TYPE_TASK_LIST => Some(GroupLabels {
            key: "task_lists",
            name: "TASK_LISTS",
            title: "Task Lists",
        }),
        ENTITY_TYPE_TASK => Some(GroupLabels {
            key: "tasks",
            name: "TASKS",
            title: "Tasks",
        }),
        ENTITY_TYPE_MACHINE => Some(GroupLabels {
            key: "machines",
            name: "MACHINES",
            title: "Machines",
        }),
        ENTITY_TYPE_FEDERATION_GRANT => Some(GroupLabels {
            key: "federation_grants",
            name: "FEDERATION_GRANTS",
            title: "Federation Grants",
        }),
        _ => None,
    }
}

fn group_key(entity_type: u8) -> &'static str {
    group_labels(entity_type).key
}

fn group_name(entity_type: u8) -> &'static str {
    group_labels(entity_type).name
}

fn group_title(entity_type: u8) -> &'static str {
    group_labels(entity_type).title
}

fn fields_for_profile(entity_type: u8, profile: FieldProfile) -> &'static [&'static str] {
    match (entity_type, profile) {
        // CLAIM profiles are prefixes of the pinned on-disk key set (D11) —
        // sourced from `claim::CLAIM_BODY_KEYS` so the read projection can
        // never drift from the storage ABI:
        //   Minimal  = pred val
        //   Standard = pred val conf sal evid
        //   Full     = pred val conf sal evid from to src world subj scope
        (ENTITY_TYPE_CLAIM, FieldProfile::Minimal) => crate::claim::CLAIM_FIELDS_MINIMAL,
        (ENTITY_TYPE_CLAIM, FieldProfile::Standard) => crate::claim::CLAIM_FIELDS_STANDARD,
        (ENTITY_TYPE_CLAIM, FieldProfile::Full) => crate::claim::CLAIM_FIELDS_FULL,

        (ENTITY_TYPE_TURN, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_TURN, FieldProfile::Standard) => &["txt", "spkr", "at"],
        (ENTITY_TYPE_TURN, FieldProfile::Full) => &["txt", "spkr", "at", "sess"],

        (ENTITY_TYPE_SUMMARY, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Standard) => &["txt", "lvl", "at"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Full) => &["txt", "lvl", "at", "src"],

        (ENTITY_TYPE_EVENT, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_EVENT, FieldProfile::Standard) => &["name", "at", "ppl"],
        (ENTITY_TYPE_EVENT, FieldProfile::Full) => &["name", "at", "ppl", "place", "desc"],

        (ENTITY_TYPE_PERSON, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Standard) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Full) => &["name", "role", "rel"],

        (ENTITY_TYPE_SKILL, FieldProfile::Minimal) => &["skillId"],
        (ENTITY_TYPE_SKILL, FieldProfile::Standard) => &["skillId", "desc", "approvalStatus"],
        (ENTITY_TYPE_SKILL, FieldProfile::Full) => &[
            "skillId",
            "desc",
            "version",
            "approvalStatus",
            "lifecycleStatus",
            "source",
            "confidence",
        ],

        // TaskList (project container)
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Standard) => &["name", "goal", "status"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Full) => {
            &["name", "goal", "status", "icon", "color", "repoUrl"]
        }

        // Task (universal work unit)
        (ENTITY_TYPE_TASK, FieldProfile::Minimal) => &["title", "role"],
        (ENTITY_TYPE_TASK, FieldProfile::Standard) => {
            &["title", "role", "status", "priority", "dueDate"]
        }
        (ENTITY_TYPE_TASK, FieldProfile::Full) => &[
            "title",
            "role",
            "status",
            "priority",
            "dueDate",
            "frequency",
            "frequencyDetail",
            "currentStreak",
            "longestStreak",
            "parentId",
            "listId",
            "position",
        ],

        // Machine: schema-reserved, no fields yet. Explicit empty arms so
        // future field additions don't silently fall through to alphabetical order.
        (ENTITY_TYPE_MACHINE, _) => &[],

        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Minimal) => {
            crate::federation::FEDERATION_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Standard) => {
            crate::federation::FEDERATION_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Full) => {
            crate::federation::FEDERATION_GRANT_FIELDS_FULL
        }

        _ => &[],
    }
}

fn append_stats_line(out: &mut String, stats: &PackStats, format: PackFormat) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }

    let ms = stats.query_time_us as f64 / 1000.0;
    let signals = stats
        .signals_used
        .iter()
        .map(|signal| signal_name(*signal))
        .collect::<Vec<_>>()
        .join(",");

    let mut stats_line = format!(
        "query: {ms:.1}ms | {} candidates | signals: {} | cosine ghosts dampened: {}",
        stats.candidates_considered, signals, stats.cosine_ghosts_dampened
    );
    if stats.items_truncated.count > 0 {
        stats_line.push_str(&format!(
            " | truncated: {} {}",
            stats.items_truncated.count,
            stats.items_truncated.reason.as_str()
        ));
    }
    if stats.items_dropped.count > 0 {
        stats_line.push_str(&format!(
            " | dropped: {} {}",
            stats.items_dropped.count,
            stats.items_dropped.reason.as_str()
        ));
    }
    if format == PackFormat::Yaml {
        out.push_str("# ");
        out.push_str(&stats_line);
        out.push('\n');
    } else {
        out.push_str("---\n");
        out.push_str(&stats_line);
    }
}

fn json_stats(pack_stats: &PackStats) -> Value {
    let mut stats = Map::new();
    stats.insert(
        "candidates".to_owned(),
        Value::Number(Number::from(pack_stats.candidates_considered as u64)),
    );
    stats.insert(
        "signals".to_owned(),
        Value::Array(
            pack_stats
                .signals_used
                .iter()
                .map(|signal| Value::String(signal_name(*signal).to_owned()))
                .collect(),
        ),
    );
    stats.insert(
        "query_us".to_owned(),
        Value::Number(Number::from(pack_stats.query_time_us)),
    );
    stats.insert(
        "hydrated".to_owned(),
        Value::Number(Number::from(pack_stats.entities_hydrated as u64)),
    );
    stats.insert(
        "neighbors_hydrated".to_owned(),
        Value::Number(Number::from(pack_stats.neighbors_hydrated as u64)),
    );
    stats.insert(
        "cosine_ghosts_dampened".to_owned(),
        Value::Number(Number::from(pack_stats.cosine_ghosts_dampened as u64)),
    );
    if pack_stats.items_truncated.count > 0 {
        stats.insert(
            "truncated".to_owned(),
            item_accounting_json(pack_stats.items_truncated),
        );
    }
    if pack_stats.items_dropped.count > 0 {
        stats.insert(
            "dropped".to_owned(),
            item_accounting_json(pack_stats.items_dropped),
        );
    }
    Value::Object(stats)
}

fn item_accounting_json(accounting: crate::types::PackItemAccounting) -> Value {
    let mut out = Map::new();
    out.insert(
        "count".to_owned(),
        Value::Number(Number::from(accounting.count as u64)),
    );
    out.insert(
        "reason".to_owned(),
        Value::String(accounting.reason.as_str().to_owned()),
    );
    Value::Object(out)
}

fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
    }
}

fn value_to_text(value: &Value, spaced_arrays: bool) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => v.clone(),
        Value::Array(values) => {
            let sep = if spaced_arrays { ", " } else { "," };
            values
                .iter()
                .map(|value| value_to_text(value, spaced_arrays))
                .collect::<Vec<_>>()
                .join(sep)
        }
        Value::Object(_) => value_to_compact_string(value),
    }
}

fn value_to_compact_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[cfg(test)]
fn estimate_value_chars(value: &Value) -> usize {
    estimate_value_chars_with_depth_limit(value, None)
}

fn estimate_value_chars_with_depth_limit(
    value: &Value,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    estimate_value_chars_at_depth(value, value_depth_limit, 0)
}

fn estimate_value_chars_at_depth(
    value: &Value,
    value_depth_limit: ValueDepthLimit,
    depth: usize,
) -> usize {
    if value_depth_limit_reached(value_depth_limit, depth) {
        return 4;
    }

    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => estimate_json_string_chars(text),
        Value::Array(values) => {
            if values.is_empty() {
                2
            } else {
                2 + values
                    .iter()
                    .map(|value| estimate_value_chars_at_depth(value, value_depth_limit, depth + 1))
                    .sum::<usize>()
                    + (values.len() - 1)
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                2
            } else {
                let pairs_len: usize = map
                    .iter()
                    .map(|(key, value)| {
                        estimate_json_string_chars(key)
                            + 1
                            + estimate_value_chars_at_depth(value, value_depth_limit, depth + 1)
                    })
                    .sum();
                2 + pairs_len + (map.len() - 1)
            }
        }
    }
}

fn estimate_json_string_chars(text: &str) -> usize {
    let mut len = 2;
    for ch in text.chars() {
        len += match ch {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            '\u{08}' | '\u{0C}' => 2,
            c if (c as u32) <= 0x1F => 6,
            c => c.len_utf8(),
        };
    }
    len
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn escape_plaintext(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "\\n")
}

fn yaml_key(key: &str) -> String {
    if needs_yaml_quotes(key) {
        format!("\"{}\"", yaml_escape_quoted(key))
    } else {
        key.to_owned()
    }
}

/// Escape a string for YAML double-quoted scalar output.
/// Handles backslash, double-quote, tab, and other control characters
/// following libyaml's escape table.
fn yaml_escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0B' => out.push_str("\\v"),
            '\x0C' => out.push_str("\\f"),
            '\x1B' => out.push_str("\\e"),
            c if c.is_control() => {
                let n = c as u32;
                if n <= 0xFF {
                    out.push_str(&format!("\\x{n:02X}"));
                } else {
                    out.push_str(&format!("\\u{n:04X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn normalize_group_entity_type(entity_type: u8) -> u8 {
    if known_group_labels(entity_type).is_some() {
        entity_type
    } else {
        OTHER_ENTITY_TYPE
    }
}

fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => {
            if needs_yaml_quotes(v) {
                format!("\"{}\"", yaml_escape_quoted(v))
            } else {
                v.clone()
            }
        }
        // Flow arrays: always quote string elements to avoid comma/colon ambiguity
        Value::Array(values) => {
            let inner = values
                .iter()
                .map(|v| match v {
                    Value::String(s) => format!("\"{}\"", yaml_escape_quoted(s)),
                    other => yaml_scalar(other),
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{inner}]")
        }
        Value::Object(_) => format!(
            "\"{}\"",
            yaml_escape_quoted(&value_to_compact_string(value))
        ),
    }
}

/// Check if a YAML plain scalar would be ambiguous (parsed as non-string type)
/// or contains characters that require quoting. Follows serde-yml/libyaml rules.
fn needs_yaml_quotes(value: &str) -> bool {
    value.is_empty()
        // YAML indicators at start position
        || value.starts_with(['-', '?', ':', '!', '&', '*', '#', '{', '[', '>', '|', '\'', '"', '%', '@', '`', '+', '.'])
        // Flow/block indicators anywhere
        || value.contains(':')
        || value.contains('#')
        || value.contains('[')
        || value.contains(']')
        || value.contains('{')
        || value.contains('}')
        || value.contains(',')
        || value.contains('\\')
        || value.contains('\n')
        || value.contains('\t')
        // Leading/trailing whitespace
        || value.starts_with(' ')
        || value.ends_with(' ')
        // YAML 1.1 boolean/null aliases (all case variants)
        || is_yaml_reserved_word(value)
        || looks_numeric(value)
}

fn is_yaml_reserved_word(value: &str) -> bool {
    matches!(
        value,
        "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "null"
            | "~"
            | "True"
            | "False"
            | "Yes"
            | "No"
            | "On"
            | "Off"
            | "Null"
            | "TRUE"
            | "FALSE"
            | "YES"
            | "NO"
            | "ON"
            | "OFF"
            | "NULL"
            | "y"
            | "Y"
            | "n"
            | "N"
            | "nil"
            | "Nil"
            | "NIL"
    )
}

fn looks_numeric(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let s = if value.starts_with(['+', '-']) {
        &value[1..]
    } else {
        value
    };
    if s.is_empty() {
        return false;
    }
    // Pure integer
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // Float (including .5, 1., 1.0, 1e10)
    if s.parse::<f64>().is_ok() {
        return true;
    }
    // YAML special floats and hex/octal
    let lower = s.to_ascii_lowercase();
    matches!(lower.as_str(), ".inf" | ".nan" | "inf" | "nan")
        || lower.starts_with("0x")
        || lower.starts_with("0o")
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::types::{
        ContextEntity, ContextPack, EmptyContext, EmptyReason, EntityId, FieldProfile, PackFormat,
        PackStats, Signal, TokenAllocation,
    };

    use super::*;

    fn sample_pack() -> ContextPack {
        let mut claim_fields = HashMap::new();
        claim_fields.insert("pred".to_owned(), Value::String("goal.learning".to_owned()));
        claim_fields.insert(
            "val".to_owned(),
            Value::String("Learn Japanese by June".to_owned()),
        );
        claim_fields.insert(
            "evid".to_owned(),
            Value::Array(vec![
                Value::String("tn17:a1".to_owned()),
                Value::String("tn23:c4".to_owned()),
            ]),
        );

        let mut turn_fields = HashMap::new();
        turn_fields.insert(
            "txt".to_owned(),
            Value::String("I really want to learn Japanese".to_owned()),
        );
        turn_fields.insert("spkr".to_owned(), Value::String("user".to_owned()));
        turn_fields.insert(
            "at".to_owned(),
            Value::Number(Number::from(
                crate::unix_seconds_now().saturating_sub(3 * 86_400),
            )),
        );

        ContextPack {
            results: vec![
                ContextEntity {
                    id: EntityId::from_bytes_unchecked([1; 16]),
                    short_id: "cl88".to_owned(),
                    content_hash: 0xf2,
                    entity_type: 0,
                    score: 0.42,
                    fields: Some(claim_fields),
                    edges: None,
                    vector: None,
                },
                ContextEntity {
                    id: EntityId::from_bytes_unchecked([2; 16]),
                    short_id: "tn17".to_owned(),
                    content_hash: 0xa1,
                    entity_type: 1,
                    score: 0.39,
                    fields: Some(turn_fields),
                    edges: None,
                    vector: None,
                },
            ],
            neighbors: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([3; 16]),
                short_id: "pr05".to_owned(),
                content_hash: 0xb3,
                entity_type: 4,
                score: 0.0,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String("Alice".to_owned()),
                )])),
                edges: None,
                vector: None,
            }],
            stats: PackStats {
                candidates_considered: 45,
                signals_used: vec![Signal::Vector, Signal::Text, Signal::Temporal],
                query_time_us: 2_100,
                entities_hydrated: 2,
                neighbors_hydrated: 1,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                items_truncated: crate::types::PackItemAccounting::item_budget(),
                items_dropped: crate::types::PackItemAccounting::token_budget(),
            },
            empty: None,
        }
    }

    fn config(format: PackFormat) -> SerializeConfig {
        SerializeConfig {
            format,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        }
    }

    fn savings_config(format: PackFormat, profile: FieldProfile) -> SerializeConfig {
        SerializeConfig {
            format,
            profile,
            budget: 0,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        }
    }

    fn prepared_entity_for_test(id_len: usize, fields: Vec<(String, Value)>) -> PreparedEntity {
        PreparedEntity {
            entity_type: 0,
            score: 0.0,
            source: PreparedEntitySource::Result,
            source_id: [0x01; 16],
            id: "x".repeat(id_len),
            fields,
        }
    }

    fn nested_child_value(depth: usize, leaf: Value) -> Value {
        let mut value = leaf;
        for _ in 0..depth {
            let mut object = Map::new();
            object.insert("child".to_owned(), value);
            value = Value::Object(object);
        }
        value
    }

    fn nested_child_object(depth: usize) -> Value {
        nested_child_value(depth, Value::String("leaf".to_owned()))
    }

    fn child_value_at_depth(value: &Value, depth: usize) -> Option<&Value> {
        let mut current = value;
        for _ in 0..depth {
            current = current.as_object()?.get("child")?;
        }
        Some(current)
    }

    fn claim_entity(seed: u8, predicate: &str, value: &str, score: f32) -> ContextEntity {
        claim_entity_with_value(seed, predicate, Value::String(value.to_owned()), score)
    }

    fn claim_entity_with_value(
        seed: u8,
        predicate: &str,
        value: Value,
        score: f32,
    ) -> ContextEntity {
        ContextEntity {
            id: EntityId::from_bytes_unchecked([seed; 16]),
            short_id: format!("cl{seed:02}"),
            content_hash: seed,
            entity_type: ENTITY_TYPE_CLAIM,
            score,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String(predicate.to_owned())),
                ("val".to_owned(), value),
            ])),
            edges: None,
            vector: None,
        }
    }

    fn pack_with_results(results: Vec<ContextEntity>) -> ContextPack {
        ContextPack {
            results,
            neighbors: Vec::new(),
            stats: empty_stats(),
            empty: None,
        }
    }

    fn token_savings_regression_pack() -> ContextPack {
        let mut pack = ContextPack {
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: PackStats {
                candidates_considered: 28,
                signals_used: vec![Signal::Vector, Signal::Text, Signal::Temporal],
                query_time_us: 3_800,
                entities_hydrated: 28,
                neighbors_hydrated: 0,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                items_truncated: crate::types::PackItemAccounting::item_budget(),
                items_dropped: crate::types::PackItemAccounting::token_budget(),
            },
            empty: None,
        };

        let now = crate::unix_seconds_now();

        for i in 0..10_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([20 + i; 16]),
                short_id: format!("cl{i:02}"),
                content_hash: 0x40 + i,
                entity_type: 0,
                score: 0.92 - f32::from(i) * 0.02,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String(format!("priority.claim.{i}"))),
                    (
                        "val".to_owned(),
                        Value::String(format!(
                            "Claim {i} captures the current architecture decision, expected impact, and rollout constraint for the active workstream."
                        )),
                    ),
                    (
                        "conf".to_owned(),
                        Value::Number(Number::from_f64(0.71 + f64::from(i) * 0.01).expect("finite confidence")),
                    ),
                    (
                        "sal".to_owned(),
                        Value::Number(Number::from_f64(0.88 - f64::from(i) * 0.01).expect("finite salience")),
                    ),
                    (
                        "evid".to_owned(),
                        Value::Array(vec![
                            Value::String(format!("tn{i:02}:aa")),
                            Value::String(format!("sm{:02}:bb", i % 3)),
                        ]),
                    ),
                    (
                        "from".to_owned(),
                        Value::Number(Number::from(
                            now.saturating_sub(((u64::from(i) + 1) * 86_400) + 3_600),
                        )),
                    ),
                    (
                        "to".to_owned(),
                        Value::Number(Number::from(
                            now.saturating_add(((u64::from(i) + 2) * 86_400) + 3_600),
                        )),
                    ),
                    (
                        "src".to_owned(),
                        Value::String(format!(
                            "research-log://autopilot/claims/{i}/evidence-chain/response-format-savings-regression"
                        )),
                    ),
                    ("world".to_owned(), Value::String("oneiron.autopilot".to_owned())),
                    (
                        "subj".to_owned(),
                        Value::String(format!("response-format-savings-target-{i}")),
                    ),
                    (
                        "scope".to_owned(),
                        Value::String(format!(
                            "Scope note {i}: preserve compact serializer output while carrying enough metadata for audits, provenance review, and future regression diagnosis."
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
        }

        for i in 0..15_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([0x90 + i; 16]),
                short_id: format!("tn{i:02}"),
                content_hash: 0x70 + i,
                entity_type: 1,
                score: 0.74 - f32::from(i) * 0.01,
                fields: Some(HashMap::from([
                    (
                        "txt".to_owned(),
                        Value::String(format!(
                            "Turn {i}: reviewer asks whether compact outputs still carry the critical claim, turn, and summary context without excess envelope bytes."
                        )),
                    ),
                    (
                        "spkr".to_owned(),
                        Value::String(if i % 2 == 0 { "user" } else { "assistant" }.to_owned()),
                    ),
                    (
                        "at".to_owned(),
                        Value::Number(Number::from(now.saturating_sub((u64::from(i) + 1) * 3_600))),
                    ),
                    (
                        "sess".to_owned(),
                        Value::String(format!(
                            "architecture-review-session-response-format-token-budget-{i:02}"
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
        }

        for i in 0..3_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([100 + i; 16]),
                short_id: format!("sm{i:02}"),
                content_hash: 0xa0 + i,
                entity_type: 8,
                score: 0.65 - f32::from(i) * 0.03,
                fields: Some(HashMap::from([
                    (
                        "txt".to_owned(),
                        Value::String(format!(
                            "Summary {i}: the pack gathers recent implementation details, reviewer concerns, acceptance criteria, and follow-up constraints for token-efficient response formats."
                        )),
                    ),
                    ("lvl".to_owned(), Value::String("session".to_owned())),
                    (
                        "at".to_owned(),
                        Value::Number(Number::from(now.saturating_sub((u64::from(i) + 1) * 7_200))),
                    ),
                    (
                        "src".to_owned(),
                        Value::String(format!(
                            "summary-source://oneiron/autopilot/response-format-regression/{i}/expanded-provenance"
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
        }

        pack
    }

    fn serialized_len(pack: &ContextPack, format: PackFormat, profile: FieldProfile) -> usize {
        serialize_pack(pack, &savings_config(format, profile)).len()
    }

    fn savings_ratio(json_full_len: usize, compact_len: usize) -> f64 {
        assert!(
            json_full_len > 0,
            "json_full_len must be > 0 for savings ratio computation"
        );
        1.0 - (compact_len as f64 / json_full_len as f64)
    }

    #[test]
    fn json_round_trip() {
        let pack = sample_pack();
        let bytes = serialize_pack(&pack, &config(PackFormat::Json));
        let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
        assert!(parsed.get("claims").is_some());
        assert!(parsed.get("turns").is_some());
    }

    #[test]
    fn toon_contains_group_header() {
        let pack = sample_pack();
        let bytes = serialize_pack(&pack, &config(PackFormat::Toon));
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("claims"));
    }

    #[test]
    fn toon_native_encoder_serializes_nested_and_tabular_sections() {
        let groups = vec![
            (
                ENTITY_TYPE_CLAIM,
                vec![PreparedEntity {
                    entity_type: ENTITY_TYPE_CLAIM,
                    score: 0.0,
                    source: PreparedEntitySource::Result,
                    source_id: [0x02; 16],
                    id: "cl88:f2".to_owned(),
                    fields: vec![
                        ("pred".to_owned(), Value::String("goal.learning".to_owned())),
                        ("val".to_owned(), Value::String("Learn Japanese".to_owned())),
                        (
                            "evid".to_owned(),
                            Value::Array(vec![
                                Value::String("tn17:a1".to_owned()),
                                Value::String("tn23:c4".to_owned()),
                            ]),
                        ),
                    ],
                }],
            ),
            (
                ENTITY_TYPE_TURN,
                vec![
                    PreparedEntity {
                        entity_type: ENTITY_TYPE_TURN,
                        score: 0.0,
                        source: PreparedEntitySource::Result,
                        source_id: [0x03; 16],
                        id: "tn17:a1".to_owned(),
                        fields: vec![
                            ("spkr".to_owned(), Value::String("user".to_owned())),
                            ("txt".to_owned(), Value::String("hello, world".to_owned())),
                        ],
                    },
                    PreparedEntity {
                        entity_type: ENTITY_TYPE_TURN,
                        score: 0.0,
                        source: PreparedEntitySource::Result,
                        source_id: [0x04; 16],
                        id: "tn23:c4".to_owned(),
                        fields: vec![
                            ("spkr".to_owned(), Value::String("assistant".to_owned())),
                            ("txt".to_owned(), Value::String("false".to_owned())),
                        ],
                    },
                ],
            ),
        ];

        let text = encode_toon_section(&groups);

        assert_eq!(
            text,
            "claims[1]:\n  - id: \"cl88:f2\"\n    pred: goal.learning\n    val: Learn Japanese\n    evid[2]: \"tn17:a1\",\"tn23:c4\"\nturns[2]{id,spkr,txt}:\n  \"tn17:a1\",user,\"hello, world\"\n  \"tn23:c4\",assistant,\"false\""
        );
    }

    #[test]
    fn toon_native_encoder_uses_list_form_for_arrays_of_empty_objects() {
        let groups = vec![(
            ENTITY_TYPE_EVENT,
            vec![PreparedEntity {
                entity_type: ENTITY_TYPE_EVENT,
                score: 0.0,
                source: PreparedEntitySource::Result,
                source_id: [0x05; 16],
                id: "ev01:01".to_owned(),
                fields: vec![(
                    "meta".to_owned(),
                    Value::Array(vec![Value::Object(Map::new()), Value::Object(Map::new())]),
                )],
            }],
        )];

        let text = encode_toon_section(&groups);

        assert_eq!(
            text,
            "events[1]:\n  - id: \"ev01:01\"\n    meta[2]:\n      -\n      -"
        );
    }

    #[test]
    fn toon_native_encoder_replaces_values_beyond_max_depth_with_null() {
        let groups = vec![(
            ENTITY_TYPE_EVENT,
            vec![PreparedEntity {
                entity_type: ENTITY_TYPE_EVENT,
                score: 0.0,
                source: PreparedEntitySource::Result,
                source_id: [0x06; 16],
                id: "ev01:01".to_owned(),
                fields: vec![("meta".to_owned(), nested_child_object(TOON_MAX_DEPTH + 8))],
            }],
        )];

        let text = encode_toon_section(&groups);

        assert!(
            text.contains("child: null"),
            "depth-limited TOON should emit null sentinel: {text}"
        );
        assert!(
            !text.contains("leaf"),
            "depth-limited TOON should not serialize the too-deep leaf: {text}"
        );
    }

    #[test]
    fn toon_bounded_truncate_strings_stops_at_depth_cap() {
        let leaf = "deep field value that should remain untouched".repeat(8);
        let mut value = nested_child_value(TOON_MAX_DEPTH + 8, Value::String(leaf.clone()));

        truncate_strings_with_depth_limit(&mut value, 4, Some(TOON_MAX_DEPTH));

        assert_eq!(
            child_value_at_depth(&value, TOON_MAX_DEPTH + 8).and_then(Value::as_str),
            Some(leaf.as_str()),
            "truncation must not walk past the TOON value-depth cap"
        );
    }

    #[test]
    fn toon_bounded_estimate_value_chars_stops_at_depth_cap() {
        let value = nested_child_value(
            TOON_MAX_DEPTH + 8,
            Value::String("deep field value that should not be counted".repeat(256)),
        );
        let expected = (0..TOON_MAX_DEPTH).fold(4, |chars, _| {
            2 + estimate_json_string_chars("child") + 1 + chars
        });

        assert_eq!(
            estimate_value_chars_with_depth_limit(&value, Some(TOON_MAX_DEPTH)),
            expected,
            "bounded estimation should price the capped subtree as null"
        );
        assert!(
            estimate_value_chars(&value) > expected,
            "unbounded estimation should still account for the deep leaf"
        );
    }

    #[test]
    fn toon_preparation_caps_deep_values_before_item_budget_estimation() {
        let value = nested_child_value(
            TOON_MAX_DEPTH + 16,
            Value::String("deep field value that would exceed the item budget".repeat(256)),
        );
        let pack = pack_with_results(vec![claim_entity_with_value(1, "note.deep", value, 1.0)]);

        let mut cfg = config(PackFormat::Toon);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 512;
        cfg.budget = 0;

        let prepared = prepare_pack(&pack, &cfg, false);
        let claims = prepared
            .results
            .iter()
            .find_map(|(entity_type, rows)| (*entity_type == ENTITY_TYPE_CLAIM).then_some(rows))
            .expect("claim group");
        let prepared_value = claims[0]
            .fields
            .iter()
            .find_map(|(key, value)| (key == "val").then_some(value))
            .expect("prepared value");

        assert_eq!(
            child_value_at_depth(prepared_value, TOON_MAX_DEPTH),
            Some(&Value::Null),
            "TOON preparation should prune at the writer depth cap before encoding"
        );
        assert_eq!(prepared.stats.items_truncated.count, 0);
        assert_eq!(prepared.stats.items_dropped.count, 0);
    }

    #[test]
    fn markdown_has_table_layout() {
        let pack = sample_pack();
        let bytes = serialize_pack(&pack, &config(PackFormat::Markdown));
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("## Claims"));
        assert!(text.contains("|----|"));
    }

    #[test]
    fn plaintext_has_compact_rows() {
        let pack = sample_pack();
        let bytes = serialize_pack(&pack, &config(PackFormat::Plaintext));
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("CLAIMS"));
        assert!(text.contains("cl88:f2|"));
    }

    #[test]
    fn yaml_has_claims_key() {
        let pack = sample_pack();
        let bytes = serialize_pack(&pack, &config(PackFormat::Yaml));
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("claims:"));
        assert!(text.contains("- id:"));
    }

    #[test]
    fn split_mode_uses_shared_budget_pool() {
        let mut pack = ContextPack {
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: empty_stats(),
            empty: None,
        };

        for i in 0..6_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([10 + i; 16]),
                short_id: format!("r{i}"),
                content_hash: i,
                entity_type: 0,
                score: 1.0,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("p".to_owned())),
                    ("val".to_owned(), Value::String("v".repeat(12))),
                ])),
                edges: None,
                vector: None,
            });
            pack.neighbors.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([30 + i; 16]),
                short_id: format!("n{i}"),
                content_hash: i,
                entity_type: 4,
                score: 0.0,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String("neighbor".to_owned()),
                )])),
                edges: None,
                vector: None,
            });
        }

        let mut cfg = config(PackFormat::Toon);
        cfg.merge_neighbors = false;
        cfg.budget = 30;

        let prepared = prepare_pack(&pack, &cfg, false);
        let total_chars =
            estimate_groups_chars(&prepared.results) + estimate_groups_chars(&prepared.neighbors);

        assert!(
            total_chars <= cfg.budget * 4,
            "shared split-mode budget should cap total chars: {total_chars}"
        );
        assert!(!prepared.results.is_empty());
        assert!(!prepared.neighbors.is_empty());
    }

    #[test]
    fn split_rebudgeting_reuses_consumed_slack_without_overshooting_total_cap() {
        let allocation = TokenAllocation::default();
        let results_source = vec![(
            0,
            vec![
                prepared_entity_for_test(18, Vec::new()),
                prepared_entity_for_test(1, Vec::new()),
            ],
        )];
        let neighbors_source = vec![(
            4,
            vec![
                prepared_entity_for_test(18, Vec::new()),
                prepared_entity_for_test(1, Vec::new()),
            ],
        )];

        let (results, neighbors) =
            budget_split_sections(&results_source, &neighbors_source, &allocation, 80);
        let total_chars = estimate_groups_chars(&results) + estimate_groups_chars(&neighbors);

        assert_eq!(results[0].1.len(), 1);
        assert_eq!(neighbors[0].1.len(), 1);
        assert!(
            total_chars <= 80,
            "rebudgeted sections should stay within the shared cap: {total_chars}"
        );
    }

    #[test]
    fn field_profile_changes_output() {
        let pack = sample_pack();

        let mut minimal = config(PackFormat::Json);
        minimal.profile = FieldProfile::Minimal;
        let minimal_json: Value = serde_json::from_slice(&serialize_pack(&pack, &minimal)).unwrap();

        let mut full = config(PackFormat::Json);
        full.profile = FieldProfile::Full;
        let full_json: Value = serde_json::from_slice(&serialize_pack(&pack, &full)).unwrap();

        let minimal_claim = &minimal_json["claims"][0];
        let full_claim = &full_json["claims"][0];
        assert!(minimal_claim.get("conf").is_none());
        assert!(full_claim.get("pred").is_some());
    }

    #[test]
    fn max_field_chars_truncates_nested_json_strings() {
        let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([42; 16]),
                short_id: "js01".to_owned(),
                content_hash: 0x42,
                entity_type: OTHER_ENTITY_TYPE,
                score: 0.7,
                fields: Some(HashMap::from([(
                    "payload".to_owned(),
                    serde_json::json!({
                        "object": {
                            "label": "abcdef",
                            "short": "ok",
                        },
                        "array": [
                            "ghijklmnop",
                            {
                                "label": "mnopqr",
                            },
                        ],
                    }),
                )])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 4;

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
        let payload = &parsed["other"][0]["payload"];

        for (value, expected) in [
            (&payload["object"]["label"], "abc…"),
            (&payload["array"][0], "ghi…"),
            (&payload["array"][1]["label"], "mno…"),
        ] {
            let text = value.as_str().expect("nested string");
            assert_eq!(text, expected);
            assert_eq!(text.chars().count(), 4);
            assert!(text.ends_with('…'));
        }

        assert_eq!(payload["object"]["short"], "ok");
    }

    #[test]
    fn serialization_token_savings_regressions() {
        // (case_name, format, profile, min_savings_vs_json_full)
        // Each row asserts the compact (format, profile) pair saves at least
        // `min_savings` fraction of bytes vs the json/Full baseline.
        let cases: &[(&str, PackFormat, FieldProfile, f64)] = &[
            ("toon_minimal", PackFormat::Toon, FieldProfile::Minimal, 0.6),
            (
                "toon_standard",
                PackFormat::Toon,
                FieldProfile::Standard,
                0.45,
            ),
            (
                "plaintext_standard",
                PackFormat::Plaintext,
                FieldProfile::Standard,
                0.55,
            ),
        ];

        let pack = token_savings_regression_pack();
        let json_full_len = serialized_len(&pack, PackFormat::Json, FieldProfile::Full);

        for (name, format, profile, threshold) in cases {
            let compact_len = serialized_len(&pack, *format, *profile);
            let savings = savings_ratio(json_full_len, compact_len);
            assert!(
                savings >= *threshold,
                "case {name}: savings {savings:.3} below {threshold:.2}; json_full_len={json_full_len}, compact_len={compact_len}"
            );
        }
    }

    #[test]
    fn short_id_serialization_uses_at_most_two_tokens_per_reference() {
        let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([42; 16]),
                short_id: "cl42".to_owned(),
                content_hash: 0x2a,
                entity_type: 0,
                score: 0.5,
                fields: Some(HashMap::from([
                    (
                        "pred".to_owned(),
                        Value::String("goal.compact-id".to_owned()),
                    ),
                    (
                        "val".to_owned(),
                        Value::String("Keep compact claim references cheap.".to_owned()),
                    ),
                ])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        let bytes = serialize_pack(
            &pack,
            &savings_config(PackFormat::Plaintext, FieldProfile::Minimal),
        );
        let text = String::from_utf8(bytes).expect("utf8");
        let rendered_ref = text
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == ':'))
            .find(|part| part.starts_with("cl42"))
            .expect("cl42 reference in serialized output");
        let short_id = rendered_ref.split(':').next().expect("short id segment");
        let estimated_bpe_tokens = rendered_ref.len().div_ceil(4);

        assert!(
            short_id.is_ascii() && short_id.len() <= 6,
            "short id reference should fit <= 6 ASCII bytes: short_id={short_id:?}, bytes={}",
            short_id.len()
        );
        assert!(
            rendered_ref.is_ascii() && estimated_bpe_tokens <= 2,
            "rendered short id reference should fit <= 2 estimated BPE tokens: rendered_ref={rendered_ref:?}, bytes={}, estimated_bpe_tokens={estimated_bpe_tokens}",
            rendered_ref.len()
        );
        assert!(
            text.contains("cl42:2a"),
            "serialized output should include rendered short id with hash: {text}"
        );
    }

    #[test]
    fn token_budget_truncates_groups() {
        let mut pack = sample_pack();
        for i in 0..40_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([50 + i; 16]),
                short_id: format!("cl{i}"),
                content_hash: i,
                entity_type: 0,
                score: 0.3,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("p".to_owned())),
                    ("val".to_owned(), Value::String("v".repeat(64))),
                ])),
                edges: None,
                vector: None,
            });
        }

        let total_claims = pack.results.iter().filter(|e| e.entity_type == 0).count();

        let mut cfg = config(PackFormat::Toon);
        cfg.budget = 100;
        let prepared = prepare_pack(&pack, &cfg, false);
        let claims_len = prepared
            .results
            .iter()
            .find_map(|(et, rows)| (*et == 0).then_some(rows.len()))
            .unwrap_or(0);
        assert!(claims_len < total_claims);
    }

    #[test]
    fn max_item_tokens_truncates_string_with_exact_suffix() {
        let long_value = "x".repeat(1200);
        let pack = pack_with_results(vec![claim_entity(1, "note.long", &long_value, 1.0)]);

        let mut cfg = config(PackFormat::Json);
        cfg.include_stats = true;
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 32;

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
        let rendered = parsed["claims"][0]["val"]
            .as_str()
            .expect("truncated string value");
        let suffix = "...(truncated, 1200 chars total)";

        assert!(rendered.ends_with(suffix), "rendered={rendered}");
        assert_ne!(rendered, long_value);
        assert_eq!(parsed["stats"]["truncated"]["count"], 1);
        assert_eq!(parsed["stats"]["truncated"]["reason"], "item_budget");
    }

    #[test]
    fn max_item_tokens_preserves_claim_predicate_when_value_is_shorter() {
        let predicate = format!("note.{}", "predicate".repeat(15));
        let value = "v".repeat(120);
        let pack = pack_with_results(vec![claim_entity(1, &predicate, &value, 1.0)]);

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 64;

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
        let rendered_value = parsed["claims"][0]["val"]
            .as_str()
            .expect("truncated string value");

        assert_eq!(
            parsed["claims"][0]["pred"].as_str(),
            Some(predicate.as_str())
        );
        assert!(rendered_value.ends_with("...(truncated, 120 chars total)"));
        assert_ne!(rendered_value, value);
    }

    #[test]
    fn max_item_tokens_preserves_claim_predicate_for_non_string_value() {
        let predicate = format!("note.{}", "predicate".repeat(15));
        let mut object = Map::new();
        object.insert("summary".to_owned(), Value::String("s".repeat(300)));
        object.insert("confidence".to_owned(), Value::Number(Number::from(7)));
        let original_value = Value::Object(object);
        let original_value_chars = estimate_value_chars(&original_value);
        let pack = pack_with_results(vec![claim_entity_with_value(
            1,
            &predicate,
            original_value,
            1.0,
        )]);

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 64;

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
        let rendered_value = parsed["claims"][0]["val"]
            .as_str()
            .expect("truncated non-string value");

        assert_eq!(
            parsed["claims"][0]["pred"].as_str(),
            Some(predicate.as_str())
        );
        assert_eq!(
            rendered_value,
            format!("...(truncated, {original_value_chars} chars total)")
        );
    }

    #[test]
    fn max_item_tokens_strips_claim_to_safe_minimal_row_when_value_truncation_is_not_enough() {
        let predicate = "note.metadata_heavy";
        let mut entity = PreparedEntity {
            entity_type: ENTITY_TYPE_CLAIM,
            score: 1.0,
            source: PreparedEntitySource::Result,
            source_id: [0x07; 16],
            id: "cl01:01".to_owned(),
            fields: vec![
                ("pred".to_owned(), Value::String(predicate.to_owned())),
                ("val".to_owned(), Value::String("v".repeat(120))),
                ("src".to_owned(), Value::String("s".repeat(300))),
                ("scope".to_owned(), Value::String("c".repeat(300))),
            ],
        };
        let mut stats = empty_stats();

        assert!(apply_item_budget(&mut entity, 32, &mut stats));

        assert!(estimate_entity_chars(&entity) <= 32 * 4);
        assert_eq!(
            entity
                .fields
                .iter()
                .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten()),
            Some(predicate)
        );
        assert!(entity.fields.iter().any(|(key, _)| key == "val"));
        assert!(!entity.fields.iter().any(|(key, _)| key == "src"));
        assert!(!entity.fields.iter().any(|(key, _)| key == "scope"));
        assert_eq!(stats.items_truncated.count, 1);
        assert_eq!(stats.items_dropped.count, 0);
    }

    #[test]
    fn max_item_tokens_strips_claim_metadata_without_truncating_short_value() {
        let predicate = "note.metadata_heavy";
        let mut entity = PreparedEntity {
            entity_type: ENTITY_TYPE_CLAIM,
            score: 1.0,
            source: PreparedEntitySource::Result,
            source_id: [0x08; 16],
            id: "cl01:01".to_owned(),
            fields: vec![
                ("pred".to_owned(), Value::String(predicate.to_owned())),
                ("val".to_owned(), Value::String("ok".to_owned())),
                ("src".to_owned(), Value::String("s".repeat(300))),
                ("scope".to_owned(), Value::String("c".repeat(300))),
            ],
        };
        let mut stats = empty_stats();

        assert!(apply_item_budget(&mut entity, 32, &mut stats));

        assert!(estimate_entity_chars(&entity) <= 32 * 4);
        assert_eq!(
            entity
                .fields
                .iter()
                .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten()),
            Some(predicate)
        );
        assert_eq!(
            entity
                .fields
                .iter()
                .find_map(|(key, value)| (key == "val").then_some(value.as_str()).flatten()),
            Some("ok")
        );
        assert!(!entity.fields.iter().any(|(key, _)| key == "src"));
        assert!(!entity.fields.iter().any(|(key, _)| key == "scope"));
        assert_eq!(stats.items_truncated.count, 1);
        assert_eq!(stats.items_dropped.count, 0);
    }

    #[test]
    fn max_item_tokens_trims_multiple_non_claim_strings_until_under_cap() {
        let mut entity = PreparedEntity {
            entity_type: ENTITY_TYPE_TURN,
            score: 1.0,
            source: PreparedEntitySource::Result,
            source_id: [0x09; 16],
            id: "tn01:01".to_owned(),
            fields: vec![
                ("txt".to_owned(), Value::String("a".repeat(160))),
                ("note".to_owned(), Value::String("b".repeat(160))),
            ],
        };
        let mut stats = empty_stats();

        assert!(apply_item_budget(&mut entity, 40, &mut stats));

        assert!(estimate_entity_chars(&entity) <= 40 * 4);
        assert_eq!(stats.items_truncated.count, 1);
        assert_eq!(stats.items_dropped.count, 0);
        for (_, value) in &entity.fields {
            let rendered = value.as_str().expect("string field");
            assert!(rendered.ends_with("...(truncated, 160 chars total)"));
        }
    }

    #[test]
    fn max_item_tokens_replaces_non_claim_without_safe_strings_with_minimal_row() {
        let mut entity = PreparedEntity {
            entity_type: ENTITY_TYPE_EVENT,
            score: 1.0,
            source: PreparedEntitySource::Result,
            source_id: [0x0A; 16],
            id: "ev01:01".to_owned(),
            fields: vec![
                (
                    "meta".to_owned(),
                    Value::Array((0..200).map(|i| Value::Number(Number::from(i))).collect()),
                ),
                ("weight".to_owned(), Value::Number(Number::from(42))),
            ],
        };
        let mut stats = empty_stats();

        assert!(apply_item_budget(&mut entity, 8, &mut stats));

        assert!(entity.fields.is_empty());
        assert!(estimate_entity_chars(&entity) <= 8 * 4);
        assert_eq!(stats.items_truncated.count, 1);
        assert_eq!(stats.items_dropped.count, 0);
    }

    #[test]
    fn max_item_tokens_drops_rows_when_tiny_budget_cannot_fit_suffix_or_minimal_row() {
        let pack = pack_with_results(vec![claim_entity(1, "note.tiny", &"x".repeat(200), 1.0)]);

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 1;
        cfg.budget = 0;

        let prepared = prepare_pack(&pack, &cfg, true);

        assert!(prepared.results.is_empty());
        assert_eq!(prepared.stats.items_truncated.count, 0);
        assert_eq!(prepared.stats.items_dropped.count, 1);
        assert_eq!(prepared.stats.items_dropped.reason.as_str(), "item_budget");
    }

    #[test]
    fn item_and_token_budget_reasons_are_discriminated() {
        let over_item = "a".repeat(400);
        let budget_drop = "fits item cap but not total budget";
        let pack = pack_with_results(vec![
            claim_entity(1, "note.over_item", &over_item, 1.0),
            claim_entity(2, "note.budget_drop", budget_drop, 0.5),
        ]);

        let mut cfg = config(PackFormat::Toon);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 24;
        cfg.budget = 30;

        let prepared = prepare_pack(&pack, &cfg, false);
        let kept_rows: usize = prepared.results.iter().map(|(_, rows)| rows.len()).sum();

        assert_eq!(kept_rows, 1);
        assert_eq!(prepared.stats.items_truncated.count, 1);
        assert_eq!(
            prepared.stats.items_truncated.reason.as_str(),
            "item_budget"
        );
        assert_eq!(prepared.stats.items_dropped.count, 1);
        assert_eq!(prepared.stats.items_dropped.reason.as_str(), "token_budget");
    }

    #[test]
    fn critical_predicate_claims_bypass_item_cap_and_drop_path() {
        let critical_value = "c".repeat(1200);
        let pack = pack_with_results(vec![claim_entity(
            1,
            "preference.food",
            &critical_value,
            1.0,
        )]);

        let mut cfg = config(PackFormat::Toon);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 8;
        cfg.budget = 1;

        let prepared = prepare_pack(&pack, &cfg, false);
        let kept = prepared
            .results
            .iter()
            .find_map(|(entity_type, rows)| (*entity_type == ENTITY_TYPE_CLAIM).then_some(rows))
            .expect("critical claim group");
        let rendered_value = kept[0]
            .fields
            .iter()
            .find_map(|(key, value)| (key == "val").then_some(value.as_str()).flatten())
            .expect("critical value");

        assert_eq!(rendered_value, critical_value);
        assert_eq!(prepared.stats.items_truncated.count, 0);
        assert_eq!(prepared.stats.items_dropped.count, 0);
    }

    #[test]
    fn max_item_tokens_zero_preserves_oversized_output_and_zero_counts() {
        let long_value = "z".repeat(1200);
        let pack = pack_with_results(vec![claim_entity(1, "note.disabled", &long_value, 1.0)]);

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 0;

        let bytes = serialize_pack(&pack, &cfg);
        let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
        let prepared = prepare_pack(&pack, &cfg, true);

        assert_eq!(
            parsed["claims"][0]["val"].as_str(),
            Some(long_value.as_str())
        );
        assert!(
            !String::from_utf8(bytes)
                .expect("utf8")
                .contains("...(truncated,")
        );
        assert_eq!(prepared.stats.items_truncated.count, 0);
        assert_eq!(prepared.stats.items_dropped.count, 0);
    }

    #[test]
    fn over_cap_items_increment_truncated_once_each() {
        let pack = pack_with_results(vec![
            claim_entity(1, "note.first", &"a".repeat(300), 1.0),
            claim_entity(2, "note.second", &"b".repeat(300), 0.9),
        ]);

        let mut cfg = config(PackFormat::Json);
        cfg.max_field_chars = 0;
        cfg.max_item_tokens = 24;

        let prepared = prepare_pack(&pack, &cfg, true);

        assert_eq!(prepared.stats.items_truncated.count, 2);
        assert_eq!(
            prepared.stats.items_truncated.reason.as_str(),
            "item_budget"
        );
        assert_eq!(prepared.stats.items_dropped.count, 0);
    }

    #[test]
    fn token_budget_zero_disables_budget_enforcement() {
        let mut pack = sample_pack();
        for i in 0..12_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([50 + i; 16]),
                short_id: format!("cl{i}"),
                content_hash: i,
                entity_type: 0,
                score: 0.3,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("p".to_owned())),
                    ("val".to_owned(), Value::String("v".repeat(64))),
                ])),
                edges: None,
                vector: None,
            });
        }

        let total_results = pack.results.len();
        let total_neighbors = pack.neighbors.len();

        let mut cfg = config(PackFormat::Toon);
        cfg.budget = 0;
        cfg.merge_neighbors = false;

        let prepared = prepare_pack(&pack, &cfg, false);
        let kept_results: usize = prepared.results.iter().map(|(_, rows)| rows.len()).sum();
        let kept_neighbors: usize = prepared.neighbors.iter().map(|(_, rows)| rows.len()).sum();

        assert_eq!(kept_results, total_results);
        assert_eq!(kept_neighbors, total_neighbors);
    }

    #[test]
    fn max_field_chars_zero_disables_and_one_emits_ellipsis() {
        let overlong = "overlong claim value".to_owned();
        let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([42; 16]),
                short_id: "cl42".to_owned(),
                content_hash: 0x42,
                entity_type: 0,
                score: 0.5,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("goal.note".to_owned())),
                    ("val".to_owned(), Value::String(overlong.clone())),
                ])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        let mut unlimited = config(PackFormat::Json);
        unlimited.merge_neighbors = true;
        unlimited.max_field_chars = 0;
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &unlimited)).expect("json");
        assert_eq!(parsed["claims"][0]["val"].as_str(), Some(overlong.as_str()));

        let mut single_char = config(PackFormat::Json);
        single_char.merge_neighbors = true;
        single_char.max_field_chars = 1;
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &single_char)).expect("json");
        assert_eq!(parsed["claims"][0]["val"].as_str(), Some("…"));
    }

    #[test]
    fn zero_section_budget_drops_all_rows() {
        let allocation = TokenAllocation::default();
        let source = vec![(0, vec![prepared_entity_for_test(18, Vec::new())])];

        let (groups, used) = budget_groups(&source, &allocation, 0);

        assert!(groups.is_empty());
        assert_eq!(used, 0);
    }

    #[test]
    fn empty_groups_are_omitted() {
        let mut pack = sample_pack();
        pack.results.retain(|entity| entity.entity_type != 0);

        let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Markdown))).unwrap();
        assert!(!text.contains("## Claims"));
    }

    #[test]
    fn relative_timestamps_render_for_llm_formats() {
        let pack = sample_pack();
        let text =
            String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
        assert!(text.contains("-3d") || text.contains("-2d") || text.contains("-4d"));
    }

    #[test]
    fn short_id_hash_format_is_applied() {
        let pack = sample_pack();
        let text =
            String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
        assert!(text.contains("cl88:f2"));
    }

    #[test]
    fn grouping_priority_orders_claims_before_turns() {
        let pack = sample_pack();
        let text =
            String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
        let claims_pos = text.find("CLAIMS").unwrap_or(usize::MAX);
        let turns_pos = text.find("TURNS").unwrap_or(usize::MAX);
        assert!(claims_pos < turns_pos);
    }

    #[test]
    fn plaintext_escapes_pipes() {
        let mut pack = sample_pack();
        if let Some(fields) = pack.results[0].fields.as_mut() {
            fields.insert("val".to_owned(), Value::String("hello|world".to_owned()));
        }

        let text =
            String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
        assert!(text.contains("hello\\|world"));
    }

    #[test]
    fn multiple_other_types_share_normalized_budget() {
        let mut pack = sample_pack();
        pack.results.clear();
        pack.neighbors.clear();

        let row_text = "v".repeat(45);

        for i in 0..8_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([10 + i; 16]),
                short_id: format!("cl{i}"),
                content_hash: i,
                entity_type: 0,
                score: 1.0,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("p".to_owned())),
                    ("val".to_owned(), Value::String(row_text.clone())),
                ])),
                edges: None,
                vector: None,
            });

            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([40 + i; 16]),
                short_id: format!("tn{i}"),
                content_hash: i,
                entity_type: 1,
                score: 1.0,
                fields: Some(HashMap::from([(
                    "txt".to_owned(),
                    Value::String(row_text.clone()),
                )])),
                edges: None,
                vector: None,
            });

            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([80 + i; 16]),
                short_id: format!("sm{i}"),
                content_hash: i,
                entity_type: 8,
                score: 1.0,
                fields: Some(HashMap::from([(
                    "txt".to_owned(),
                    Value::String(row_text.clone()),
                )])),
                edges: None,
                vector: None,
            });

            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([120 + i; 16]),
                short_id: format!("pr{i}"),
                content_hash: i,
                entity_type: 4,
                score: 1.0,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String(row_text.clone()),
                )])),
                edges: None,
                vector: None,
            });

            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([160 + i; 16]),
                short_id: format!("ev{i}"),
                content_hash: i,
                entity_type: 6,
                score: 1.0,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String(row_text.clone()),
                )])),
                edges: None,
                vector: None,
            });
        }

        let mut cfg = config(PackFormat::Toon);
        cfg.budget = 200;
        let prepared = prepare_pack(&pack, &cfg, false);

        let persons_count = prepared
            .results
            .iter()
            .find_map(|(entity_type, rows)| (*entity_type == 4).then_some(rows.len()))
            .unwrap_or(0);
        let events_count = prepared
            .results
            .iter()
            .find_map(|(entity_type, rows)| (*entity_type == 6).then_some(rows.len()))
            .unwrap_or(0);

        assert_eq!(
            persons_count, 1,
            "persons should be constrained by normalized 'other' share"
        );
        assert_eq!(
            events_count, 1,
            "events should be constrained by normalized 'other' share"
        );
    }

    #[test]
    fn unknown_entity_types_share_single_other_group() {
        let pack = ContextPack {
            results: vec![
                ContextEntity {
                    id: EntityId::from_bytes_unchecked([18; 16]),
                    short_id: "u18".to_owned(),
                    content_hash: 0x18,
                    entity_type: 18,
                    score: 0.9,
                    fields: Some(HashMap::from([(
                        "name".to_owned(),
                        Value::String("eighteen".to_owned()),
                    )])),
                    edges: None,
                    vector: None,
                },
                ContextEntity {
                    id: EntityId::from_bytes_unchecked([20; 16]),
                    short_id: "u20".to_owned(),
                    content_hash: 0x20,
                    entity_type: 20,
                    score: 0.8,
                    fields: Some(HashMap::from([(
                        "name".to_owned(),
                        Value::String("twenty".to_owned()),
                    )])),
                    edges: None,
                    vector: None,
                },
            ],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &config(PackFormat::Json)))
                .expect("json");
        let other = parsed
            .get("other")
            .and_then(Value::as_array)
            .expect("other group");
        assert_eq!(other.len(), 2);
        assert_eq!(other[0]["name"], "eighteen");
        assert_eq!(other[1]["name"], "twenty");
    }

    #[test]
    fn yaml_stats_are_emitted_as_comments() {
        let mut cfg = config(PackFormat::Yaml);
        cfg.include_stats = true;

        let text = String::from_utf8(serialize_pack(&sample_pack(), &cfg)).expect("utf8");
        assert!(text.contains("# query:"));
        assert!(!text.contains("\n---\nquery:"));
    }

    #[test]
    fn yaml_quotes_unsafe_field_keys() {
        let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([0x92; 16]),
                short_id: "mc01".to_owned(),
                content_hash: 0x01,
                entity_type: ENTITY_TYPE_MACHINE,
                score: 0.5,
                fields: Some(HashMap::from([
                    ("x:y".to_owned(), Value::String("value".to_owned())),
                    ("true".to_owned(), Value::String("reserved".to_owned())),
                ])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        let text =
            String::from_utf8(serialize_pack(&pack, &config(PackFormat::Yaml))).expect("utf8");
        assert!(text.contains("\"x:y\": value"));
        assert!(text.contains("\"true\": reserved"));
    }

    #[test]
    fn estimate_value_chars_matches_compact_json() {
        let values = vec![
            Value::Null,
            Value::Bool(true),
            Value::String("hello\nworld".to_owned()),
            serde_json::json!(["alpha", 3, false]),
            serde_json::json!({"a": "b", "nested": {"x": [1, 2, {"k": "v"}]}}),
        ];

        for value in values {
            assert_eq!(
                estimate_value_chars(&value),
                serde_json::to_string(&value).expect("json").len()
            );
        }
    }

    #[test]
    fn estimate_json_string_chars_matches_serde_json_escape_rules() {
        let values = [
            "",
            "plain",
            "line\nbreak",
            "\u{1F}",
            "\u{7F}",
            "\u{85}",
            "\"\\",
        ];

        for value in values {
            assert_eq!(
                estimate_json_string_chars(value),
                serde_json::to_string(value).expect("json").len(),
                "mismatch for {value:?}"
            );
        }
    }

    #[test]
    fn estimate_entity_chars_accounts_for_escaped_field_names() {
        let plain = prepared_entity_for_test(
            16,
            vec![("ab".to_owned(), Value::String("value".to_owned()))],
        );
        let escaped = prepared_entity_for_test(
            16,
            vec![("a\"".to_owned(), Value::String("value".to_owned()))],
        );

        let plain_json = serde_json::to_string(&json_rows(std::slice::from_ref(&plain), false)[0])
            .expect("json");
        let escaped_json =
            serde_json::to_string(&json_rows(std::slice::from_ref(&escaped), false)[0])
                .expect("json");

        assert_eq!(
            estimate_entity_chars(&escaped).saturating_sub(estimate_entity_chars(&plain)),
            escaped_json.len().saturating_sub(plain_json.len())
        );
    }

    #[test]
    fn surplus_budget_redistributes_to_hungry_types() {
        // 1 tiny turn + 40 fat claims with a tight budget.
        // The turn barely uses its allocation, so surplus should flow to claims.
        // Verify claims gets more entities than its raw fraction would allow.
        let mut pack = sample_pack();
        pack.results.clear();
        pack.neighbors.clear();

        // Single turn — very small, won't fill its allocation.
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([99; 16]),
            short_id: "tn01".to_owned(),
            content_hash: 0x01,
            entity_type: 1,
            score: 0.5,
            fields: Some(HashMap::from([(
                "txt".to_owned(),
                Value::String("hi".to_owned()),
            )])),
            edges: None,
            vector: None,
        });

        // 40 claims — will exceed claims budget at low token limits.
        for i in 0..40_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([50 + i; 16]),
                short_id: format!("cl{i}"),
                content_hash: i,
                entity_type: 0,
                score: 0.3,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String("p".to_owned())),
                    ("val".to_owned(), Value::String("v".repeat(40))),
                ])),
                edges: None,
                vector: None,
            });
        }

        // Budget = 200 tokens = 800 chars.
        // Raw claims fraction = 0.45, so without redistribution claims
        // would get at most floor(0.45 * 800) = 360 chars.
        // Each claim ≈ 76 chars → ~4 claims from raw fraction alone.
        // With normalization (0.45/0.55 = 0.818) → 654 chars → ~8 claims.
        // With redistribution of unused turn budget → ~770 chars → ~10 claims.
        // So claims_count should exceed the raw-fraction baseline of ~4.
        let mut cfg = config(PackFormat::Toon);
        cfg.budget = 200;
        let prepared = prepare_pack(&pack, &cfg, false);

        let claims_count = prepared
            .results
            .iter()
            .find_map(|(et, rows)| (*et == 0).then_some(rows.len()))
            .unwrap_or(0);

        // Raw fraction baseline: 0.45 * 800 = 360 chars.
        let raw_char_budget = (800.0 * 0.45) as usize;
        let avg_entity_chars = 76_usize; // approximate per claim
        let raw_baseline = raw_char_budget / avg_entity_chars;

        assert!(
            claims_count > raw_baseline,
            "redistribution should give claims more than raw {raw_baseline}: got {claims_count}"
        );
        // Turn should still be present (it fits easily).
        let turns_count = prepared
            .results
            .iter()
            .find_map(|(et, rows)| (*et == 1).then_some(rows.len()))
            .unwrap_or(0);
        assert!(turns_count > 0);
    }

    // ── TaskList and Task productivity-band tests ──────────────────

    fn empty_stats() -> PackStats {
        PackStats {
            candidates_considered: 0,
            signals_used: vec![],
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            items_truncated: crate::types::PackItemAccounting::item_budget(),
            items_dropped: crate::types::PackItemAccounting::token_budget(),
        }
    }

    fn empty_pack_with_reason(reason: EmptyReason) -> ContextPack {
        ContextPack {
            results: vec![],
            neighbors: vec![],
            stats: empty_stats(),
            empty: Some(EmptyContext {
                reason,
                total_in_scope: 7,
                hint: "test hint".to_owned(),
            }),
        }
    }

    #[test]
    fn empty_reason_json_wire_literals_are_stable() {
        for (reason, expected) in [
            (EmptyReason::FilterMatchedNone, "filter_matched_none"),
            (EmptyReason::NoData, "no_data"),
            (EmptyReason::AllActivated, "all_activated"),
            (EmptyReason::BelowThreshold, "below_threshold"),
        ] {
            let pack = empty_pack_with_reason(reason);
            let parsed: Value =
                serde_json::from_slice(&serialize_pack(&pack, &config(PackFormat::Json)))
                    .expect("json");
            assert_eq!(parsed["empty"]["reason"], expected);
            assert_eq!(parsed["empty"]["totalInScope"], 7);
            assert_eq!(parsed["empty"]["hint"], "test hint");
            let decoded: EmptyReason =
                serde_json::from_value(parsed["empty"]["reason"].clone()).expect("empty reason");
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn non_empty_json_omits_empty_key() {
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&sample_pack(), &config(PackFormat::Json)))
                .expect("json");
        assert!(
            parsed.get("empty").is_none(),
            "non-empty pack must omit the empty key"
        );
    }

    #[test]
    fn productivity_field_profiles() {
        // (case_name, entity_type, short_id, content_hash, group_key,
        //  raw_fields, present_in_standard_json, absent_from_standard_json,
        //  expected_standard_order, extra_assertions)
        //
        // `extra_assertions` runs after the common JSON/Standard checks; use it for
        // per-variant tails (plaintext rendering, full-profile membership checks,
        // Minimal-profile ordering). It receives `(pack, fields_for_profile_fn)` so
        // it can build additional configs as needed.
        struct Case<'a> {
            name: &'a str,
            entity_type: u8,
            short_id: &'a str,
            content_hash: u8,
            group_key: &'a str,
            build_fields: fn() -> HashMap<String, Value>,
            present_in_standard: &'a [&'a str],
            absent_from_standard: &'a [&'a str],
            expected_standard_order: &'a [&'a str],
            extra: fn(&ContextPack),
        }

        fn task_list_fields() -> HashMap<String, Value> {
            let mut fields = HashMap::new();
            fields.insert("name".to_owned(), Value::String("Sprint 42".to_owned()));
            fields.insert(
                "description".to_owned(),
                Value::String("Q2 deliverables".to_owned()),
            );
            fields.insert("goal".to_owned(), Value::String("Ship the MVP".to_owned()));
            fields.insert("icon".to_owned(), Value::String("rocket".to_owned()));
            fields.insert("status".to_owned(), Value::String("active".to_owned()));
            // Extras only in Full / fallback.
            fields.insert("color".to_owned(), Value::String("#ff0000".to_owned()));
            fields.insert(
                "repoUrl".to_owned(),
                Value::String("https://github.com/example".to_owned()),
            );
            fields
        }

        fn task_fields() -> HashMap<String, Value> {
            let mut fields = HashMap::new();
            fields.insert("role".to_owned(), Value::String("habit".to_owned()));
            fields.insert("title".to_owned(), Value::String("Morning run".to_owned()));
            fields.insert("status".to_owned(), Value::String("active".to_owned()));
            fields.insert(
                "dueDate".to_owned(),
                Value::Number(Number::from(
                    crate::unix_seconds_now().saturating_add(2 * 86_400),
                )),
            );
            fields.insert("priority".to_owned(), Value::Number(Number::from(2_u64)));
            fields.insert("frequency".to_owned(), Value::String("daily".to_owned()));
            // Extras only in Full.
            fields.insert(
                "frequencyDetail".to_owned(),
                Value::String("weekdays".to_owned()),
            );
            fields.insert(
                "currentStreak".to_owned(),
                Value::Number(Number::from(5_u64)),
            );
            fields
        }

        fn task_list_extra(pack: &ContextPack) {
            // Re-assert specific value equality for Standard fields (was in the
            // original test_task_list_field_profiles via assert_eq!).
            let cfg_json = SerializeConfig {
                format: PackFormat::Json,
                profile: FieldProfile::Standard,
                budget: 4000,
                allocation: TokenAllocation::default(),
                include_stats: false,
                merge_neighbors: true,
                max_field_chars: 500,
                max_item_tokens: 0,
            };
            let parsed: Value =
                serde_json::from_slice(&serialize_pack(pack, &cfg_json)).expect("json parse");
            let first = &parsed["task_lists"][0];
            assert_eq!(first["name"], "Sprint 42");
            assert_eq!(first["goal"], "Ship the MVP");
            assert_eq!(first["status"], "active");

            // Plaintext Standard: assert group-name uppercasing + short_id:hash + text payload.
            let cfg_plain = SerializeConfig {
                format: PackFormat::Plaintext,
                profile: FieldProfile::Standard,
                budget: 4000,
                allocation: TokenAllocation::default(),
                include_stats: false,
                merge_neighbors: true,
                max_field_chars: 500,
                max_item_tokens: 0,
            };
            let text = String::from_utf8(serialize_pack(pack, &cfg_plain)).expect("utf8");
            assert!(
                text.contains("TASK_LISTS"),
                "group name should be TASK_LISTS"
            );
            assert!(text.contains("tl01:aa"), "short_id:hash should appear");
            assert!(text.contains("Sprint 42"));
            assert!(text.contains("Ship the MVP"));
        }

        fn task_extra(pack: &ContextPack) {
            // Re-assert specific string value equality for title/role/status
            // (was in the original test_task_field_profiles via assert_eq!).
            let cfg_json = SerializeConfig {
                format: PackFormat::Json,
                profile: FieldProfile::Standard,
                budget: 4000,
                allocation: TokenAllocation::default(),
                include_stats: false,
                merge_neighbors: true,
                max_field_chars: 500,
                max_item_tokens: 0,
            };
            let parsed: Value =
                serde_json::from_slice(&serialize_pack(pack, &cfg_json)).expect("json parse");
            let first = &parsed["tasks"][0];
            assert_eq!(first["title"], "Morning run");
            assert_eq!(first["role"], "habit");
            assert_eq!(first["status"], "active");

            // Minimal ordering for TASK.
            let minimal = fields_for_profile(ENTITY_TYPE_TASK, FieldProfile::Minimal);
            assert_eq!(minimal, &["title", "role"]);

            // Full membership for TASK.
            let full = fields_for_profile(ENTITY_TYPE_TASK, FieldProfile::Full);
            assert!(full.contains(&"frequency"));
            assert!(full.contains(&"frequencyDetail"));
            assert!(full.contains(&"currentStreak"));
            assert!(full.contains(&"longestStreak"));
            assert!(full.contains(&"parentId"));
            assert!(full.contains(&"listId"));
            assert!(full.contains(&"position"));
        }

        let cases: &[Case] = &[
            Case {
                name: "task_list",
                entity_type: ENTITY_TYPE_TASK_LIST,
                short_id: "tl01",
                content_hash: 0xaa,
                group_key: "task_lists",
                build_fields: task_list_fields,
                present_in_standard: &["name", "goal", "status"],
                absent_from_standard: &["description", "icon"],
                expected_standard_order: &["name", "goal", "status"],
                extra: task_list_extra,
            },
            Case {
                name: "task",
                entity_type: ENTITY_TYPE_TASK,
                short_id: "tk01",
                content_hash: 0xbb,
                group_key: "tasks",
                build_fields: task_fields,
                present_in_standard: &["title", "role", "status", "priority", "dueDate"],
                absent_from_standard: &["frequency", "frequencyDetail", "currentStreak"],
                expected_standard_order: &["title", "role", "status", "priority", "dueDate"],
                extra: task_extra,
            },
        ];

        for case in cases {
            let entity = ContextEntity {
                id: EntityId::from_bytes_unchecked([case.entity_type; 16]),
                short_id: case.short_id.to_owned(),
                content_hash: case.content_hash,
                entity_type: case.entity_type,
                score: 0.8,
                fields: Some((case.build_fields)()),
                edges: None,
                vector: None,
            };
            let pack = ContextPack {
                results: vec![entity],
                neighbors: vec![],
                stats: empty_stats(),
                empty: None,
            };

            // JSON / Standard profile inclusion + exclusion.
            let cfg_json = SerializeConfig {
                format: PackFormat::Json,
                profile: FieldProfile::Standard,
                budget: 4000,
                allocation: TokenAllocation::default(),
                include_stats: false,
                merge_neighbors: true,
                max_field_chars: 500,
                max_item_tokens: 0,
            };
            let bytes = serialize_pack(&pack, &cfg_json);
            let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
            let group = parsed.get(case.group_key).unwrap_or_else(|| {
                panic!("case {}: missing group key {}", case.name, case.group_key)
            });
            let first = &group[0];
            for field in case.present_in_standard {
                assert!(
                    first.get(field).is_some(),
                    "case {}: field {field:?} should be present in Standard JSON",
                    case.name
                );
            }
            for field in case.absent_from_standard {
                assert!(
                    first.get(field).is_none(),
                    "case {}: field {field:?} should be absent from Standard JSON",
                    case.name
                );
            }

            // Standard profile ordering matches the documented schema.
            let standard = fields_for_profile(case.entity_type, FieldProfile::Standard);
            assert_eq!(
                standard, case.expected_standard_order,
                "case {}: Standard profile ordering mismatch",
                case.name
            );

            (case.extra)(&pack);
        }
    }

    #[test]
    fn federation_grant_member_ref_hex_projection_is_preserved() {
        let member_ref = EntityId::from_bytes_unchecked([0x42; 16]).to_hex();
        let fields = HashMap::from([
            (
                "scope".to_owned(),
                serde_json::json!({"kind": "vault", "vault_id": 7}),
            ),
            ("member_ref".to_owned(), Value::String(member_ref.clone())),
            ("role".to_owned(), Value::String("admin".to_owned())),
            ("preset".to_owned(), Value::String("admin".to_owned())),
        ]);
        let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([ENTITY_TYPE_FEDERATION_GRANT; 16]),
                short_id: String::new(),
                content_hash: 0,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                score: 1.0,
                fields: Some(fields),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };
        for profile in [FieldProfile::Standard, FieldProfile::Full] {
            let cfg_json = SerializeConfig {
                format: PackFormat::Json,
                profile,
                budget: 4000,
                allocation: TokenAllocation::default(),
                include_stats: false,
                merge_neighbors: true,
                max_field_chars: 500,
                max_item_tokens: 0,
            };

            let parsed: Value =
                serde_json::from_slice(&serialize_pack(&pack, &cfg_json)).expect("json parse");
            let first = &parsed["federation_grants"][0];

            assert_eq!(first["member_ref"], member_ref);
        }
    }

    #[test]
    fn test_due_date_timestamp_rendering() {
        // dueDate set to 2 days in the future — should render as "+2d" in plaintext.
        let now = crate::unix_seconds_now();
        let due = now + 2 * 86_400;

        let mut fields = HashMap::new();
        fields.insert("title".to_owned(), Value::String("Deploy v2".to_owned()));
        fields.insert("role".to_owned(), Value::String("task".to_owned()));
        fields.insert("status".to_owned(), Value::String("pending".to_owned()));
        fields.insert("dueDate".to_owned(), Value::Number(Number::from(due)));

        let entity = ContextEntity {
            id: EntityId::from_bytes_unchecked([0x91; 16]),
            short_id: "tk02".to_owned(),
            content_hash: 0xcc,
            entity_type: ENTITY_TYPE_TASK,
            score: 0.9,
            fields: Some(fields),
            edges: None,
            vector: None,
        };

        let pack = ContextPack {
            results: vec![entity],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        // Plaintext format renders timestamps relatively.
        let cfg = SerializeConfig {
            format: PackFormat::Plaintext,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };

        let text = String::from_utf8(serialize_pack(&pack, &cfg)).expect("utf8");

        // dueDate should be rendered as a relative timestamp, not the raw epoch integer.
        assert!(
            text.contains("+2d") || text.contains("+1d") || text.contains("+3d"),
            "dueDate should be a relative timestamp like +2d, got: {text}"
        );
        // The raw epoch number should NOT appear in the output.
        assert!(
            !text.contains(&due.to_string()),
            "raw epoch value should not appear in plaintext"
        );

        // Verify dueDate is recognized as a timestamp field.
        assert!(
            is_timestamp_field("dueDate"),
            "dueDate must be in is_timestamp_field"
        );

        // JSON format should keep the raw numeric timestamp (no relative rendering).
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };

        let json_bytes = serialize_pack(&pack, &cfg_json);
        let parsed: Value = serde_json::from_slice(&json_bytes).expect("json parse");
        let task = &parsed["tasks"][0];
        assert_eq!(
            task["dueDate"].as_u64().unwrap(),
            due,
            "JSON format should preserve raw numeric timestamp"
        );
    }

    #[test]
    fn test_group_labels_sparse_ids() {
        let asset = group_labels(ENTITY_TYPE_ASSET);
        assert_eq!(asset.key, "assets");
        assert_eq!(asset.name, "ASSETS");
        assert_eq!(asset.title, "Assets");

        let notification = group_labels(ENTITY_TYPE_NOTIFICATION);
        assert_eq!(notification.key, "notifications");
        assert_eq!(notification.name, "NOTIFICATIONS");
        assert_eq!(notification.title, "Notifications");

        let tl = group_labels(ENTITY_TYPE_TASK_LIST);
        assert_eq!(tl.key, "task_lists");
        assert_eq!(tl.name, "TASK_LISTS");
        assert_eq!(tl.title, "Task Lists");

        let tk = group_labels(ENTITY_TYPE_TASK);
        assert_eq!(tk.key, "tasks");
        assert_eq!(tk.name, "TASKS");
        assert_eq!(tk.title, "Tasks");

        let mc = group_labels(ENTITY_TYPE_MACHINE);
        assert_eq!(mc.key, "machines");
        assert_eq!(mc.name, "MACHINES");
        assert_eq!(mc.title, "Machines");

        let grant = group_labels(ENTITY_TYPE_FEDERATION_GRANT);
        assert_eq!(grant.key, "federation_grants");
        assert_eq!(grant.name, "FEDERATION_GRANTS");
        assert_eq!(grant.title, "Federation Grants");
        assert_eq!(
            fields_for_profile(ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Minimal),
            crate::federation::FEDERATION_GRANT_FIELDS_MINIMAL
        );

        // Types outside the known set should fall back to OTHER_GROUP_LABELS.
        let unknown = group_labels(255);
        assert_eq!(unknown.key, "other");
        assert_eq!(unknown.name, "OTHER");
        assert_eq!(unknown.title, "Other");
    }
}
