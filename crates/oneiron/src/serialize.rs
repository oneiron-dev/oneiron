use std::collections::{HashMap, HashSet};

use serde_json::{Map, Number, Value};

use crate::types::{ContextEntity, ContextPack, FieldProfile, PackFormat, Signal, TokenAllocation};

const GROUP_ORDER: &[u8] = &[0, 1, 8, 6, 4, 7, 10, 9];

#[derive(Debug, Clone)]
pub struct SerializeConfig {
    pub format: PackFormat,
    pub profile: FieldProfile,
    pub budget: usize,
    pub allocation: TokenAllocation,
    pub include_stats: bool,
    pub merge_neighbors: bool,
    pub max_field_chars: usize,
}

#[derive(Debug, Clone)]
struct PreparedEntity {
    entity_type: u8,
    score: f32,
    id: String,
    fields: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
struct PreparedPack {
    merged: bool,
    results: Vec<(u8, Vec<PreparedEntity>)>,
    neighbors: Vec<(u8, Vec<PreparedEntity>)>,
}

pub fn serialize_pack(pack: &ContextPack, config: &SerializeConfig) -> Vec<u8> {
    match config.format {
        PackFormat::Json => serialize_json(pack, config),
        PackFormat::Yaml => serialize_yaml(pack, config).into_bytes(),
        PackFormat::Toon => serialize_toon(pack, config).into_bytes(),
        PackFormat::Markdown => serialize_markdown(pack, config).into_bytes(),
        PackFormat::Plaintext => serialize_plaintext(pack, config).into_bytes(),
    }
}

fn serialize_json(pack: &ContextPack, config: &SerializeConfig) -> Vec<u8> {
    let prepared = prepare_pack(pack, config, true);
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
        root.insert("stats".to_owned(), json_stats(pack));
    }

    serde_json::to_vec(&Value::Object(root)).unwrap_or_else(|_| b"{}".to_vec())
}

fn serialize_toon(pack: &ContextPack, config: &SerializeConfig) -> String {
    let prepared = prepare_pack(pack, config, false);

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
        append_stats_line(&mut out, pack);
    }

    out
}

fn serialize_markdown(pack: &ContextPack, config: &SerializeConfig) -> String {
    let prepared = prepare_pack(pack, config, false);
    let mut out = String::new();

    if prepared.merged {
        write_markdown_groups(&mut out, &prepared.results, "##");
    } else {
        write_markdown_groups(&mut out, &prepared.results, "##");
        if !prepared.neighbors.is_empty() {
            if !out.is_empty() {
                out.push_str("\n---\n\n");
            }
            out.push_str("### Neighbors\n\n");
            write_markdown_groups(&mut out, &prepared.neighbors, "####");
        }
    }

    if config.include_stats {
        append_stats_line(&mut out, pack);
    }

    out
}

fn serialize_plaintext(pack: &ContextPack, config: &SerializeConfig) -> String {
    let prepared = prepare_pack(pack, config, false);
    let mut out = String::new();

    if prepared.merged {
        write_plaintext_groups(&mut out, &prepared.results);
    } else {
        write_plaintext_groups(&mut out, &prepared.results);
        if !prepared.neighbors.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str("---NEIGHBORS\n\n");
            write_plaintext_groups(&mut out, &prepared.neighbors);
        }
    }

    if config.include_stats {
        append_stats_line(&mut out, pack);
    }

    out
}

fn serialize_yaml(pack: &ContextPack, config: &SerializeConfig) -> String {
    let prepared = prepare_pack(pack, config, false);
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
        append_stats_line(&mut out, pack);
    }

    out
}

fn prepare_pack(pack: &ContextPack, config: &SerializeConfig, json_mode: bool) -> PreparedPack {
    let skip_budget = config.format == PackFormat::Json;

    if config.merge_neighbors {
        let mut merged = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
        merged.extend(prepare_entities(&pack.results, config, json_mode));
        merged.extend(prepare_entities(&pack.neighbors, config, json_mode));

        let mut groups = group_entities(merged);
        if !skip_budget {
            enforce_token_budget(&mut groups, config);
        }

        PreparedPack {
            merged: true,
            results: groups,
            neighbors: Vec::new(),
        }
    } else {
        let mut results = group_entities(prepare_entities(&pack.results, config, json_mode));
        let mut neighbors = group_entities(prepare_entities(&pack.neighbors, config, json_mode));
        if !skip_budget {
            enforce_token_budget(&mut results, config);
            enforce_token_budget(&mut neighbors, config);
        }

        PreparedPack {
            merged: false,
            results,
            neighbors,
        }
    }
}

fn prepare_entities(
    entities: &[ContextEntity],
    config: &SerializeConfig,
    json_mode: bool,
) -> Vec<PreparedEntity> {
    let now = crate::unix_seconds_now();
    entities
        .iter()
        .map(|entity| {
            let mut fields = Vec::new();

            if let Some(map) = entity.fields.as_ref() {
                let field_keys = field_keys(entity.entity_type, config.profile, map);
                for key in field_keys {
                    let Some(value) = map.get(&key) else {
                        continue;
                    };
                    let value =
                        normalize_value(&key, value, json_mode, now, config.max_field_chars);
                    fields.push((key, value));
                }
            }

            PreparedEntity {
                entity_type: entity.entity_type,
                score: entity.score,
                id: format_short_id(entity),
                fields,
            }
        })
        .collect()
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
) -> Value {
    let mut value = if !json_mode && is_timestamp_field(key) {
        if let Some(ts) = value.as_u64() {
            Value::String(format_relative_timestamp(ts, now))
        } else if let Some(ts) = value.as_i64() {
            if ts >= 0 {
                Value::String(format_relative_timestamp(ts as u64, now))
            } else {
                value.clone()
            }
        } else {
            value.clone()
        }
    } else {
        value.clone()
    };

    if max_field_chars > 0 {
        truncate_strings(&mut value, max_field_chars);
    }

    value
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

fn truncate_strings(value: &mut Value, max_field_chars: usize) {
    match value {
        Value::String(text) => {
            if text.chars().count() > max_field_chars {
                let take = max_field_chars.saturating_sub(1);
                let truncated: String = text.chars().take(take).collect();
                *text = if take == 0 {
                    "…".to_owned()
                } else {
                    format!("{truncated}…")
                };
            }
        }
        Value::Array(values) => {
            for value in values {
                truncate_strings(value, max_field_chars);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                truncate_strings(value, max_field_chars);
            }
        }
        _ => {}
    }
}

fn group_entities(entities: Vec<PreparedEntity>) -> Vec<(u8, Vec<PreparedEntity>)> {
    let mut buckets = HashMap::<u8, Vec<PreparedEntity>>::new();
    for entity in entities {
        buckets.entry(entity.entity_type).or_default().push(entity);
    }

    for rows in buckets.values_mut() {
        rows.sort_unstable_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    }

    let mut out = Vec::new();
    for entity_type in GROUP_ORDER {
        if let Some(rows) = buckets.remove(entity_type) {
            if !rows.is_empty() {
                out.push((*entity_type, rows));
            }
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

fn type_fraction(entity_type: u8, allocation: &TokenAllocation) -> f32 {
    match entity_type {
        0 => allocation.claims,
        1 => allocation.turns,
        8 => allocation.summaries,
        _ => allocation.other,
    }
}

fn enforce_token_budget(groups: &mut Vec<(u8, Vec<PreparedEntity>)>, config: &SerializeConfig) {
    if config.budget == 0 {
        return;
    }

    let char_budget = config.budget.saturating_mul(4);

    // Normalize fractions so they sum to 1.0 (multiple "other" types each
    // get allocation.other, so raw sum can exceed 1.0).
    let raw: Vec<f32> = groups
        .iter()
        .map(|(et, _)| type_fraction(*et, &config.allocation))
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
        let needed: usize = rows.iter().map(estimate_entity_chars).sum();
        if needed <= budget {
            surplus += budget - needed;
        } else {
            hungry_weight += frac;
        }
        budgets.push(budget);
        needs.push(needed);
    }

    // Second pass: redistribute surplus to hungry types, then truncate.
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

        if final_budget == 0 {
            rows.clear();
            continue;
        }

        let mut used = 0_usize;
        let mut keep = 0_usize;
        for row in rows.iter() {
            let chars = estimate_entity_chars(row);
            if used + chars > final_budget && keep > 0 {
                break;
            }
            keep += 1;
            used += chars;
        }
        rows.truncate(keep);
    }

    groups.retain(|(_, rows)| !rows.is_empty());
}

fn estimate_entity_chars(entity: &PreparedEntity) -> usize {
    let mut chars = entity.id.len() + 12;
    for (key, value) in &entity.fields {
        chars += key.len();
        chars += value_to_compact_string(value).len();
        chars += 4;
    }
    chars
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
            if include_score {
                if let Some(score) = Number::from_f64(entity.score as f64) {
                    row.insert("score".to_owned(), Value::Number(score));
                }
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

    let value = Value::Object(section_object(groups, false));
    toon_format::encode_default(&value).unwrap_or_default()
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
                out.push_str(key);
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
    let mut columns = vec!["id".to_owned()];
    let mut seen = HashSet::<String>::from(["id".to_owned()]);

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
    match entity_type {
        0 => GroupLabels {
            key: "claims",
            name: "CLAIMS",
            title: "Claims",
        },
        1 => GroupLabels {
            key: "turns",
            name: "TURNS",
            title: "Turns",
        },
        2 => GroupLabels {
            key: "sessions",
            name: "SESSIONS",
            title: "Sessions",
        },
        3 => GroupLabels {
            key: "messages",
            name: "MESSAGES",
            title: "Messages",
        },
        4 => GroupLabels {
            key: "persons",
            name: "PERSONS",
            title: "Persons",
        },
        5 => GroupLabels {
            key: "relationships",
            name: "RELATIONSHIPS",
            title: "Relationships",
        },
        6 => GroupLabels {
            key: "events",
            name: "EVENTS",
            title: "Events",
        },
        7 => GroupLabels {
            key: "skills",
            name: "SKILLS",
            title: "Skills",
        },
        8 => GroupLabels {
            key: "summaries",
            name: "SUMMARIES",
            title: "Summaries",
        },
        9 => GroupLabels {
            key: "places",
            name: "PLACES",
            title: "Places",
        },
        10 => GroupLabels {
            key: "texts",
            name: "TEXTS",
            title: "Texts",
        },
        11 => GroupLabels {
            key: "conversations",
            name: "CONVERSATIONS",
            title: "Conversations",
        },
        12 => GroupLabels {
            key: "organizations",
            name: "ORGANIZATIONS",
            title: "Organizations",
        },
        13 => GroupLabels {
            key: "facets",
            name: "FACETS",
            title: "Facets",
        },
        14 => GroupLabels {
            key: "worlds",
            name: "WORLDS",
            title: "Worlds",
        },
        // Productivity (60-79)
        60 => GroupLabels {
            key: "task_lists",
            name: "TASK_LISTS",
            title: "Task Lists",
        },
        61 => GroupLabels {
            key: "tasks",
            name: "TASKS",
            title: "Tasks",
        },
        62 => GroupLabels {
            key: "machines",
            name: "MACHINES",
            title: "Machines",
        },
        _ => OTHER_GROUP_LABELS,
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
        (0, FieldProfile::Minimal) => &["pred", "val"],
        (0, FieldProfile::Standard) => &["pred", "val", "conf", "sal", "evid"],
        (0, FieldProfile::Full) => &[
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope",
        ],

        (1, FieldProfile::Minimal) => &["txt"],
        (1, FieldProfile::Standard) => &["txt", "spkr", "at"],
        (1, FieldProfile::Full) => &["txt", "spkr", "at", "sess"],

        (8, FieldProfile::Minimal) => &["txt"],
        (8, FieldProfile::Standard) => &["txt", "lvl", "at"],
        (8, FieldProfile::Full) => &["txt", "lvl", "at", "src"],

        (6, FieldProfile::Minimal) => &["name"],
        (6, FieldProfile::Standard) => &["name", "at", "ppl"],
        (6, FieldProfile::Full) => &["name", "at", "ppl", "place", "desc"],

        (4, FieldProfile::Minimal) => &["name"],
        (4, FieldProfile::Standard) => &["name"],
        (4, FieldProfile::Full) => &["name", "role", "rel"],

        (7, FieldProfile::Minimal) => &["skillId"],
        (7, FieldProfile::Standard) => &["skillId", "desc", "approvalStatus"],
        (7, FieldProfile::Full) => &[
            "skillId",
            "desc",
            "version",
            "approvalStatus",
            "lifecycleStatus",
            "source",
            "confidence",
        ],

        // TaskList (project container)
        (60, FieldProfile::Minimal) => &["name"],
        (60, FieldProfile::Standard) => &["name", "goal", "status"],
        (60, FieldProfile::Full) => &["name", "goal", "status", "icon", "color", "repoUrl"],

        // Task (universal work unit)
        (61, FieldProfile::Minimal) => &["title", "role"],
        (61, FieldProfile::Standard) => &["title", "role", "status", "priority", "dueDate"],
        (61, FieldProfile::Full) => &[
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

        // Machine (62): schema-reserved, no fields yet. Explicit empty arms so
        // future field additions don't silently fall through to alphabetical order.
        (62, _) => &[],

        _ => &[],
    }
}

fn append_stats_line(out: &mut String, pack: &ContextPack) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }

    let ms = pack.stats.query_time_us as f64 / 1000.0;
    let signals = pack
        .stats
        .signals_used
        .iter()
        .map(|signal| signal_name(*signal))
        .collect::<Vec<_>>()
        .join(",");

    out.push_str("---\n");
    out.push_str(&format!(
        "query: {ms:.1}ms | {} candidates | signals: {}",
        pack.stats.candidates_considered, signals
    ));
}

fn json_stats(pack: &ContextPack) -> Value {
    let mut stats = Map::new();
    stats.insert(
        "candidates".to_owned(),
        Value::Number(Number::from(pack.stats.candidates_considered as u64)),
    );
    stats.insert(
        "signals".to_owned(),
        Value::Array(
            pack.stats
                .signals_used
                .iter()
                .map(|signal| Value::String(signal_name(*signal).to_owned()))
                .collect(),
        ),
    );
    stats.insert(
        "query_us".to_owned(),
        Value::Number(Number::from(pack.stats.query_time_us)),
    );
    stats.insert(
        "hydrated".to_owned(),
        Value::Number(Number::from(pack.stats.entities_hydrated as u64)),
    );
    stats.insert(
        "neighbors_hydrated".to_owned(),
        Value::Number(Number::from(pack.stats.neighbors_hydrated as u64)),
    );
    Value::Object(stats)
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

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn escape_plaintext(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "\\n")
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
        ContextEntity, ContextPack, EntityId, FieldProfile, PackFormat, PackStats, Signal,
        TokenAllocation,
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
                    id: EntityId::from_bytes([1; 16]),
                    short_id: "cl88".to_owned(),
                    content_hash: 0xf2,
                    entity_type: 0,
                    score: 0.42,
                    fields: Some(claim_fields),
                    edges: None,
                    vector: None,
                },
                ContextEntity {
                    id: EntityId::from_bytes([2; 16]),
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
                id: EntityId::from_bytes([3; 16]),
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
            },
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
        }
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
    fn token_budget_truncates_groups() {
        let mut pack = sample_pack();
        for i in 0..40_u8 {
            pack.results.push(ContextEntity {
                id: EntityId::from_bytes([50 + i; 16]),
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
                id: EntityId::from_bytes([10 + i; 16]),
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
                id: EntityId::from_bytes([40 + i; 16]),
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
                id: EntityId::from_bytes([80 + i; 16]),
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
                id: EntityId::from_bytes([120 + i; 16]),
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
                id: EntityId::from_bytes([160 + i; 16]),
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
    fn surplus_budget_redistributes_to_hungry_types() {
        // 1 tiny turn + 40 fat claims with a tight budget.
        // The turn barely uses its allocation, so surplus should flow to claims.
        // Verify claims gets more entities than its raw fraction would allow.
        let mut pack = sample_pack();
        pack.results.clear();
        pack.neighbors.clear();

        // Single turn — very small, won't fill its allocation.
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes([99; 16]),
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
                id: EntityId::from_bytes([50 + i; 16]),
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

    // ── TaskList (type 60) and Task (type 61) tests ──────────────────

    fn empty_stats() -> PackStats {
        PackStats {
            candidates_considered: 0,
            signals_used: vec![],
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
        }
    }

    #[test]
    fn test_task_list_field_profiles() {
        let mut fields = HashMap::new();
        fields.insert("name".to_owned(), Value::String("Sprint 42".to_owned()));
        fields.insert(
            "description".to_owned(),
            Value::String("Q2 deliverables".to_owned()),
        );
        fields.insert("goal".to_owned(), Value::String("Ship the MVP".to_owned()));
        fields.insert("icon".to_owned(), Value::String("rocket".to_owned()));
        fields.insert("status".to_owned(), Value::String("active".to_owned()));
        // Extra field not in any profile — should only appear when profile is empty / fallback.
        fields.insert("color".to_owned(), Value::String("#ff0000".to_owned()));
        fields.insert(
            "repoUrl".to_owned(),
            Value::String("https://github.com/example".to_owned()),
        );

        let entity = ContextEntity {
            id: EntityId::from_bytes([60; 16]),
            short_id: "tl01".to_owned(),
            content_hash: 0xaa,
            entity_type: 60,
            score: 0.8,
            fields: Some(fields),
            edges: None,
            vector: None,
        };

        let pack = ContextPack {
            results: vec![entity],
            neighbors: vec![],
            stats: empty_stats(),
        };

        // --- JSON with Standard profile ---
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
        };

        let bytes = serialize_pack(&pack, &cfg_json);
        let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");

        // Should appear under the "task_lists" group key.
        let task_lists = parsed.get("task_lists").expect("task_lists key missing");
        let first = &task_lists[0];
        assert_eq!(first["name"], "Sprint 42");
        assert_eq!(first["goal"], "Ship the MVP");
        assert_eq!(first["status"], "active");
        // Standard profile for type 60 is ["name", "goal", "status"].
        // "description" and "icon" are NOT in Standard, so they should be absent.
        assert!(
            first.get("description").is_none(),
            "description should not appear in Standard profile"
        );
        assert!(
            first.get("icon").is_none(),
            "icon should not appear in Standard profile"
        );

        // --- Plaintext with Standard profile ---
        let cfg_plain = SerializeConfig {
            format: PackFormat::Plaintext,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
        };

        let text = String::from_utf8(serialize_pack(&pack, &cfg_plain)).expect("utf8");
        assert!(
            text.contains("TASK_LISTS"),
            "group name should be TASK_LISTS"
        );
        assert!(text.contains("tl01:aa"), "short_id:hash should appear");
        assert!(text.contains("Sprint 42"));
        assert!(text.contains("Ship the MVP"));

        // --- Verify field ordering matches fields_for_profile ---
        let expected = fields_for_profile(60, FieldProfile::Standard);
        assert_eq!(expected, &["name", "goal", "status"]);
    }

    #[test]
    fn test_task_field_profiles() {
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
        // Extra fields only in Full profile.
        fields.insert(
            "frequencyDetail".to_owned(),
            Value::String("weekdays".to_owned()),
        );
        fields.insert(
            "currentStreak".to_owned(),
            Value::Number(Number::from(5_u64)),
        );

        let entity = ContextEntity {
            id: EntityId::from_bytes([61; 16]),
            short_id: "tk01".to_owned(),
            content_hash: 0xbb,
            entity_type: 61,
            score: 0.75,
            fields: Some(fields),
            edges: None,
            vector: None,
        };

        let pack = ContextPack {
            results: vec![entity],
            neighbors: vec![],
            stats: empty_stats(),
        };

        // --- JSON Standard profile ---
        let cfg = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
        };

        let bytes = serialize_pack(&pack, &cfg);
        let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");

        let tasks = parsed.get("tasks").expect("tasks key missing");
        let first = &tasks[0];
        assert_eq!(first["title"], "Morning run");
        assert_eq!(first["role"], "habit");
        assert_eq!(first["status"], "active");
        assert!(
            first.get("priority").is_some(),
            "priority should be present in Standard"
        );
        assert!(
            first.get("dueDate").is_some(),
            "dueDate should be present in Standard"
        );
        // "frequency" is NOT in Standard profile for type 61.
        assert!(
            first.get("frequency").is_none(),
            "frequency should not appear in Standard profile"
        );
        assert!(
            first.get("frequencyDetail").is_none(),
            "frequencyDetail should not appear in Standard profile"
        );
        assert!(
            first.get("currentStreak").is_none(),
            "currentStreak should not appear in Standard profile"
        );

        // --- Verify field ordering for all profiles ---
        let minimal = fields_for_profile(61, FieldProfile::Minimal);
        assert_eq!(minimal, &["title", "role"]);

        let standard = fields_for_profile(61, FieldProfile::Standard);
        assert_eq!(
            standard,
            &["title", "role", "status", "priority", "dueDate"]
        );

        let full = fields_for_profile(61, FieldProfile::Full);
        assert!(full.contains(&"frequency"));
        assert!(full.contains(&"frequencyDetail"));
        assert!(full.contains(&"currentStreak"));
        assert!(full.contains(&"longestStreak"));
        assert!(full.contains(&"parentId"));
        assert!(full.contains(&"listId"));
        assert!(full.contains(&"position"));
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
            id: EntityId::from_bytes([61; 16]),
            short_id: "tk02".to_owned(),
            content_hash: 0xcc,
            entity_type: 61,
            score: 0.9,
            fields: Some(fields),
            edges: None,
            vector: None,
        };

        let pack = ContextPack {
            results: vec![entity],
            neighbors: vec![],
            stats: empty_stats(),
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
        let tl = group_labels(60);
        assert_eq!(tl.key, "task_lists");
        assert_eq!(tl.name, "TASK_LISTS");
        assert_eq!(tl.title, "Task Lists");

        let tk = group_labels(61);
        assert_eq!(tk.key, "tasks");
        assert_eq!(tk.name, "TASKS");
        assert_eq!(tk.title, "Tasks");

        let mc = group_labels(62);
        assert_eq!(mc.key, "machines");
        assert_eq!(mc.name, "MACHINES");
        assert_eq!(mc.title, "Machines");

        // Types outside the known set should fall back to OTHER_GROUP_LABELS.
        let unknown = group_labels(255);
        assert_eq!(unknown.key, "other");
        assert_eq!(unknown.name, "OTHER");
        assert_eq!(unknown.title, "Other");
    }
}
