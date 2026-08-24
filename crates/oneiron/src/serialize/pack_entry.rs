//! Entry points and per-format dispatch for context-pack serialization.
//!
//! Note the deliberate cycle with [`super::token_budget`]: the serialized-output
//! budget and the token-stats pass both re-encode a prepared pack through
//! [`serialize_prepared_pack`] to measure its real size, so `token_budget` calls
//! back into this module. Measuring after encoding is the contract, not a layering
//! slip.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::FieldProfile;
use crate::context_pack::PackFormat;
use crate::context_pack::PackStats;
use crate::context_pack::TokenAllocation;
use crate::eiri::ResumeBundle;

use super::group_labels::group_key;
use super::json_format::{json_rows, section_object};
use super::markdown_plaintext_format::{write_markdown_groups, write_plaintext_groups};
use super::pack_preparation::prepare_pack;
use super::token_budget::{append_stats_line, json_stats};
use super::toon_format::encode_toon_section;
use super::types::GroupKey;
use super::yaml_format::write_yaml_groups;

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
pub(super) struct PreparedEntity {
    pub(super) entity_type: u8,
    pub(super) score: f32,
    pub(super) source: PreparedEntitySource,
    pub(super) source_id: [u8; 16],
    pub(super) id: String,
    pub(super) fields: Vec<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreparedEntitySource {
    Result,
    Neighbor,
}

#[derive(Debug, Clone)]
pub(super) struct PreparedPack {
    pub(super) merged: bool,
    pub(super) results: Vec<(GroupKey, Vec<PreparedEntity>)>,
    pub(super) neighbors: Vec<(GroupKey, Vec<PreparedEntity>)>,
    pub(super) stats: PackStats,
}

pub(super) type PreparedGroups = Vec<(GroupKey, Vec<PreparedEntity>)>;

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

pub(super) fn serialize_prepared_pack(
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
