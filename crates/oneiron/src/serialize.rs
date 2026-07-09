use std::collections::{HashMap, HashSet};

use serde_json::{Map, Number, Value};

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::FieldProfile;
use crate::context_pack::PackFormat;
use crate::context_pack::PackItemTokenStats;
use crate::context_pack::PackSectionTokenStats;
use crate::context_pack::PackStats;
use crate::context_pack::PackTokenStats;
use crate::context_pack::TokenAllocation;
use crate::pipeline::Signal;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_PLACE,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN,
    ENTITY_TYPE_WORLD,
};
use crate::tokenizer::{DEFAULT_CONTEXT_PACK_TOKENIZER, PackTokenizer};
use crate::types::ResumeBundle;

const GROUP_ORDER: &[u8] = &[
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_EVENT,
    ENTITY_TYPE_PERSON,
    ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_SKILL,
    ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_PLACE,
];
// Use an impossible entity type as the shared sink for unknown groups.
const OTHER_ENTITY_TYPE: u8 = u8::MAX;
// Bound native TOON recursion for user/vault-provided JSON field values.
const TOON_MAX_DEPTH: usize = 128;
type ValueDepthLimit = Option<usize>;

/// Codec label for deterministic code-run raw output previews.
pub const CODE_RUN_OUTPUT_PREVIEW_CODEC: &str = "utf8-lossy-whitespace-compact-v1";
/// Default character cap for compact code-run raw output previews.
pub const CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS: usize = 256;

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

/// Apply JSON context-pack field projection plus real-token budget controls
/// while preserving the structured `ContextPack` envelope used by HTTP APIs.
pub fn project_pack_for_json_response(
    mut pack: ContextPack,
    config: &SerializeConfig,
) -> ContextPack {
    let prepared = prepare_pack(&pack, config, true);
    let stats = prepared.stats.clone();
    let mut projected_results = HashMap::<[u8; 16], Vec<(String, Value)>>::new();
    let mut projected_neighbors = HashMap::<[u8; 16], Vec<(String, Value)>>::new();
    collect_projected_json_rows(
        prepared.results,
        &mut projected_results,
        &mut projected_neighbors,
    );
    collect_projected_json_rows(
        prepared.neighbors,
        &mut projected_results,
        &mut projected_neighbors,
    );

    pack.results = apply_projected_json_rows(pack.results, projected_results);
    pack.neighbors = apply_projected_json_rows(pack.neighbors, projected_neighbors);
    pack.stats = stats;
    pack
}

fn collect_projected_json_rows(
    groups: PreparedGroups,
    results: &mut HashMap<[u8; 16], Vec<(String, Value)>>,
    neighbors: &mut HashMap<[u8; 16], Vec<(String, Value)>>,
) {
    for (_, rows) in groups {
        for row in rows {
            match row.source {
                PreparedEntitySource::Result => {
                    results.insert(row.source_id, row.fields);
                }
                PreparedEntitySource::Neighbor => {
                    neighbors.insert(row.source_id, row.fields);
                }
            }
        }
    }
}

fn apply_projected_json_rows(
    entities: Vec<ContextEntity>,
    mut projected_rows: HashMap<[u8; 16], Vec<(String, Value)>>,
) -> Vec<ContextEntity> {
    entities
        .into_iter()
        .filter_map(|mut entity| {
            let fields = projected_rows.remove(entity.id.as_bytes())?;
            if entity.fields.is_some() {
                entity.fields = Some(HashMap::from_iter(fields));
            }
            Some(entity)
        })
        .collect()
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

/// Builds the compact text preview stored beside raw code-run output bytes.
///
/// The preview is deterministic and intentionally lossy: invalid UTF-8 is
/// replaced, runs of whitespace collapse to one ASCII space, and the result is
/// capped by `max_chars`.
#[must_use]
pub fn compressed_code_run_output_preview(raw: &[u8], max_chars: usize) -> (String, bool) {
    if raw.is_empty() || max_chars == 0 {
        return (String::new(), !raw.is_empty());
    }

    let mut compact = String::new();
    let mut previous_was_space = true;
    for ch in String::from_utf8_lossy(raw).chars() {
        if ch.is_whitespace() {
            if !previous_was_space {
                compact.push(' ');
                previous_was_space = true;
            }
        } else {
            compact.push(ch);
            previous_was_space = false;
        }
    }

    if compact.ends_with(' ') {
        compact.pop();
    }

    let mut preview = String::new();
    let mut truncated = false;
    for (index, ch) in compact.chars().enumerate() {
        if index >= max_chars {
            truncated = true;
            break;
        }
        preview.push(ch);
    }

    (preview, truncated)
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
fn budget_split_sections(
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

    let tokenizer = DEFAULT_CONTEXT_PACK_TOKENIZER;
    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return true;
    }

    let truncated = if entity.entity_type == ENTITY_TYPE_CLAIM {
        truncate_claim_value_for_item_budget(entity, max_item_tokens, tokenizer, value_depth_limit)
    } else {
        truncate_non_claim_for_item_budget(entity, max_item_tokens, tokenizer, value_depth_limit)
    };

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        if truncated {
            stats.items_truncated.count = stats.items_truncated.count.saturating_add(1);
        }
        true
    } else {
        stats.items_dropped.reason = crate::context_pack::PackItemAccountingReason::ItemBudget;
        stats.items_dropped.count = stats.items_dropped.count.saturating_add(1);
        false
    }
}

fn truncate_non_claim_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let mut truncated = false;
    let mut tried_fields = Vec::new();

    while estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        > max_item_tokens
    {
        let Some(field_index) =
            largest_truncatable_top_level_string_field(entity, tried_fields.as_slice())
        else {
            break;
        };

        tried_fields.push(field_index);
        truncated |= truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_tokens,
            tokenizer,
            value_depth_limit,
        );
    }

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    truncated | retain_structural_item_budget_fields(entity)
}

fn truncate_claim_value_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let Some(value_index) = field_index(entity, "val") else {
        return retain_minimal_claim_item_budget_fields(entity, None);
    };

    let original_value = entity.fields[value_index].1.clone();
    let mut truncated = truncate_claim_value_field_for_item_budget(
        entity,
        value_index,
        max_item_tokens,
        tokenizer,
        value_depth_limit,
    );

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    truncated |= retain_minimal_claim_item_budget_fields(entity, Some(original_value));
    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    let Some(value_index) = field_index(entity, "val") else {
        return truncated;
    };
    truncated
        | truncate_claim_value_field_for_item_budget(
            entity,
            value_index,
            max_item_tokens,
            tokenizer,
            value_depth_limit,
        )
}

fn truncate_claim_value_field_for_item_budget(
    entity: &mut PreparedEntity,
    field_index: usize,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let original_value_chars =
        estimate_value_chars_with_depth_limit(&entity.fields[field_index].1, value_depth_limit);

    match &mut entity.fields[field_index].1 {
        Value::String(_) => truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_tokens,
            tokenizer,
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
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
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

    // Character positions are only candidate cut points for preserving UTF-8
    // and human-readable suffixes. Every accepted candidate is checked with
    // the real context-pack tokenizer.
    while low <= high {
        let mid = low + ((high - low) / 2);
        entity.fields[field_index].1 =
            Value::String(truncate_with_suffix_prefix(&original, mid, &suffix));

        if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
            <= max_item_tokens
        {
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
        ENTITY_TYPE_CLAIM | ENTITY_TYPE_COMPANION_REGISTER => allocation.claims,
        ENTITY_TYPE_TURN => allocation.turns,
        ENTITY_TYPE_SUMMARY => allocation.summaries,
        _ => allocation.other,
    }
}

fn enforce_token_budget_with_depth_limit(
    groups: &mut Vec<(u8, Vec<PreparedEntity>)>,
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    if token_budget == 0 {
        let mut total_used = 0_usize;
        for (_, rows) in groups.iter_mut() {
            let mut used = 0_usize;
            rows.retain(|row| {
                let keep = is_critical_predicate_claim(row);
                if keep {
                    used = used.saturating_add(estimate_entity_tokens_with_depth_limit(
                        row,
                        tokenizer,
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
        let budget = (token_budget as f32 * frac) as usize;
        let needed: usize = rows
            .iter()
            .map(|row| estimate_entity_tokens_with_depth_limit(row, tokenizer, value_depth_limit))
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
            let tokens =
                estimate_entity_tokens_with_depth_limit(&row, tokenizer, value_depth_limit);
            if is_critical_predicate_claim(&row) {
                used = used.saturating_add(tokens);
                kept.push(row);
                continue;
            }
            if noncritical_closed {
                continue;
            }
            if used.saturating_add(tokens) > final_budget && kept_noncritical > 0 {
                noncritical_closed = true;
                continue;
            }
            kept_noncritical += 1;
            used = used.saturating_add(tokens);
            kept.push(row);
        }
        *rows = kept;
        total_used = total_used.saturating_add(used);
    }

    groups.retain(|(_, rows)| !rows.is_empty());
    total_used
}

fn estimate_entity_tokens_with_depth_limit(
    entity: &PreparedEntity,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    tokenizer.count(&entity_token_accounting_text(entity, value_depth_limit))
}

fn estimate_groups_tokens_with_depth_limit(
    groups: &[(u8, Vec<PreparedEntity>)],
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    groups
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .map(|entity| estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit))
        .sum()
}

fn entity_token_accounting_text(
    entity: &PreparedEntity,
    value_depth_limit: ValueDepthLimit,
) -> String {
    let mut row = Map::new();
    row.insert("id".to_owned(), Value::String(entity.id.clone()));
    for (key, value) in &entity.fields {
        row.insert(
            key.clone(),
            clone_value_with_depth_limit(value, value_depth_limit),
        );
    }
    serde_json::to_string(&Value::Object(row))
        .expect("prepared entity token-accounting JSON should serialize")
}

#[cfg(test)]
fn estimate_entity_chars(entity: &PreparedEntity) -> usize {
    estimate_entity_chars_with_depth_limit(entity, None)
}

// Character estimates below are retained for non-budget tests and truncation
// suffix display only. All pack budget decisions use the tokenizer helpers
// above.
#[cfg(test)]
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
fn budget_groups(
    source: &[(u8, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    token_budget: usize,
) -> (Vec<(u8, Vec<PreparedEntity>)>, usize) {
    budget_groups_with_depth_limit(
        source,
        allocation,
        token_budget,
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    )
}

fn budget_groups_with_depth_limit(
    source: &[(u8, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> (Vec<(u8, Vec<PreparedEntity>)>, usize) {
    let mut groups = source.to_vec();
    let used = enforce_token_budget_with_depth_limit(
        &mut groups,
        allocation,
        token_budget,
        tokenizer,
        value_depth_limit,
    );
    (groups, used)
}

fn enforce_serialized_token_budget(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    token_budget: usize,
    tokenizer: PackTokenizer,
) {
    // Nonzero serialized budgets take precedence over critical-row retention.
    // If every row has been removed and the fixed format envelope/stats/empty
    // scaffolding alone still exceeds `token_budget`, the budget is
    // unsatisfiable; callers get that minimal payload and `total_tokens`
    // records the actual emitted count.
    let mut may_drop_critical = false;
    while serialized_prepared_token_count(pack, config, prepared, tokenizer) > token_budget {
        if !drop_last_token_budget_item(prepared, may_drop_critical) {
            if may_drop_critical {
                break;
            }
            may_drop_critical = true;
            continue;
        }
        prepared.stats.items_dropped.reason =
            crate::context_pack::PackItemAccountingReason::TokenBudget;
        prepared.stats.items_dropped.count = prepared.stats.items_dropped.count.saturating_add(1);
    }
}

fn drop_last_token_budget_item(prepared: &mut PreparedPack, include_critical: bool) -> bool {
    if !prepared.merged
        && drop_last_token_budget_item_from_groups(&mut prepared.neighbors, include_critical)
    {
        return true;
    }

    drop_last_token_budget_item_from_groups(&mut prepared.results, include_critical)
}

fn drop_last_token_budget_item_from_groups(
    groups: &mut Vec<(u8, Vec<PreparedEntity>)>,
    include_critical: bool,
) -> bool {
    for group_index in (0..groups.len()).rev() {
        let rows = &mut groups[group_index].1;
        let Some(row_index) = rows
            .iter()
            .rposition(|row| include_critical || !is_critical_predicate_claim(row))
        else {
            continue;
        };

        rows.remove(row_index);
        if rows.is_empty() {
            groups.remove(group_index);
        }
        return true;
    }
    false
}

fn serialized_prepared_token_count(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &PreparedPack,
    tokenizer: PackTokenizer,
) -> usize {
    let bytes = serialize_prepared_pack(pack, config, prepared.clone());
    let text = std::str::from_utf8(&bytes).expect("context-pack serialization should be UTF-8");
    tokenizer.count(text)
}

fn finalize_pack_token_stats(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    tokenizer: PackTokenizer,
    token_budget: Option<usize>,
) {
    for _ in 0..16 {
        let changed = stamp_pack_token_stats(pack, config, prepared, tokenizer);
        if let Some(budget) = token_budget {
            enforce_serialized_token_budget(pack, config, prepared, budget, tokenizer);
        }

        let total_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
        let next = collect_pack_token_stats(prepared, total_tokens, tokenizer);
        let within_budget = token_budget.is_none_or(|budget| total_tokens <= budget);
        if prepared.stats.tokens == next && within_budget && !changed {
            return;
        }
        prepared.stats.tokens = next;
    }

    if let Some(budget) = token_budget {
        enforce_serialized_token_budget(pack, config, prepared, budget, tokenizer);
    }
    let _ = stamp_pack_token_stats(pack, config, prepared, tokenizer);
}

fn stamp_pack_token_stats(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    tokenizer: PackTokenizer,
) -> bool {
    let total_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
    let tokens = collect_pack_token_stats(prepared, total_tokens, tokenizer);
    let changed = prepared.stats.tokens != tokens;
    prepared.stats.tokens = tokens;
    changed
}

fn collect_pack_token_stats(
    prepared: &PreparedPack,
    total_tokens: usize,
    tokenizer: PackTokenizer,
) -> PackTokenStats {
    let mut sections = Vec::new();
    let mut items = Vec::new();
    if prepared.merged {
        collect_section_token_stats(
            "merged",
            &prepared.results,
            tokenizer,
            &mut sections,
            &mut items,
        );
    } else {
        collect_section_token_stats(
            "results",
            &prepared.results,
            tokenizer,
            &mut sections,
            &mut items,
        );
        collect_section_token_stats(
            "neighbors",
            &prepared.neighbors,
            tokenizer,
            &mut sections,
            &mut items,
        );
    }

    PackTokenStats {
        tokenizer_id: tokenizer.id().to_owned(),
        total_tokens,
        sections,
        items,
    }
}

fn collect_section_token_stats(
    section: &str,
    groups: &[(u8, Vec<PreparedEntity>)],
    tokenizer: PackTokenizer,
    sections: &mut Vec<PackSectionTokenStats>,
    items: &mut Vec<PackItemTokenStats>,
) {
    let mut section_tokens = 0_usize;
    for (entity_type, rows) in groups {
        for row in rows {
            let tokens = estimate_entity_tokens_with_depth_limit(row, tokenizer, None);
            section_tokens = section_tokens.saturating_add(tokens);
            items.push(PackItemTokenStats {
                section: section.to_owned(),
                id: row.id.clone(),
                entity_type: *entity_type,
                tokens,
            });
        }
    }

    if section_tokens > 0 || !groups.is_empty() {
        sections.push(PackSectionTokenStats {
            section: section.to_owned(),
            tokens: section_tokens,
        });
    }
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
        ENTITY_TYPE_AGENT_DEF => Some(GroupLabels {
            key: "agent_definitions",
            name: "AGENT_DEFINITIONS",
            title: "Agent Definitions",
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
        ENTITY_TYPE_ACCESS_GRANT => Some(GroupLabels {
            key: "access_grants",
            name: "ACCESS_GRANTS",
            title: "Access Grants",
        }),
        ENTITY_TYPE_COUNTERPARTY_CONTACT => Some(GroupLabels {
            key: "counterparty_contacts",
            name: "COUNTERPARTY_CONTACTS",
            title: "Counterparty Contacts",
        }),
        ENTITY_TYPE_OUTBOUND_GRANT => Some(GroupLabels {
            key: "outbound_grants",
            name: "OUTBOUND_GRANTS",
            title: "Outbound Grants",
        }),
        ENTITY_TYPE_COMPANION_REGISTER => Some(GroupLabels {
            key: "companion_records",
            name: "COMPANION_RECORDS",
            title: "Companion Records",
        }),
        ENTITY_TYPE_PSYCH_PROFILE => Some(GroupLabels {
            key: "psych_profiles",
            name: "PSYCH_PROFILES",
            title: "Psych Profiles",
        }),
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT => Some(GroupLabels {
            key: "persona_snapshot_exports",
            name: "PERSONA_SNAPSHOT_EXPORTS",
            title: "Persona Snapshot Exports",
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
        (ENTITY_TYPE_SKILL, FieldProfile::Full) => &crate::skill::SKILL_RECORD_BODY_KEYS,

        // AGENT_DEF mirrors SKILL: identity-only Minimal, identity + summary in
        // Standard, and the full pinned body only at Full — the 16 KiB
        // `instructions` prompt must never surface in Minimal/Standard packs.
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Minimal) => &["agentId"],
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Standard) => &["agentId", "desc", "approvalStatus"],
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Full) => &crate::agent_def::AGENT_DEF_BODY_KEYS,

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
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Minimal) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Standard) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Full) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_FULL
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Minimal) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Standard) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Full) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_FULL
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Minimal) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Standard) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Full) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_FULL
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Minimal) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Standard) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_STANDARD
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Full) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_FULL
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Minimal) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Standard) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Full) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL
        }
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Minimal) => &["kind", "scope", "subject"],
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Standard) => {
            &["kind", "scope", "subject", "lifecycle", "export"]
        }
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Full) => &[
            "schema_version",
            "kind",
            "scope",
            "subject",
            "lifecycle",
            "export",
            "lifecycle_events",
            "provenance",
        ],

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

fn item_accounting_json(accounting: crate::context_pack::PackItemAccounting) -> Value {
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
        || contains_yaml_control(value)
        // Leading/trailing whitespace
        || value.starts_with(' ')
        || value.ends_with(' ')
        // YAML 1.1 boolean/null aliases (all case variants)
        || is_yaml_reserved_word(value)
        || looks_numeric(value)
}

fn contains_yaml_control(value: &str) -> bool {
    value.chars().any(char::is_control)
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
mod tests;
