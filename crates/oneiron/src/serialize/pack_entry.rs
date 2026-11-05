//! Core half of `serialize::pack_entry`: its store-layer items live in `oneiron_store::serialize::pack_entry` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::serialize::pack_entry::*;

use super::group_labels::group_key;
use super::json_format::{json_rows, section_object};
use super::markdown_plaintext_format::{write_markdown_groups, write_plaintext_groups};
use super::pack_preparation::prepare_pack;
use super::token_budget::{append_stats_line, json_stats};
use super::toon_format::encode_toon_section;
use super::types::GroupKey;
use super::yaml_format::write_yaml_groups;
use crate::context_board::AssembledContext;
use crate::context_pack::ContextPack;
use crate::context_pack::PackStats;
use crate::serialize::context_entity::ContextEntity;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::FieldProfile;
use crate::serialize::pack_format::PackFormat;
use crate::tokenizer::{DEFAULT_CONTEXT_PACK_TOKENIZER, PackTokenizer};
use serde_json::{Map, Value};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(super) struct PreparedPack {
    pub(super) l2_base: Option<crate::store::l2_evidence::L2BaseSummary>,
    pub(super) merged: bool,
    pub(super) results: Vec<(GroupKey, Vec<PreparedEntity>)>,
    pub(super) neighbors: Vec<(GroupKey, Vec<PreparedEntity>)>,
    pub(super) stats: PackStats,
}

#[derive(Debug, Clone)]
pub(crate) struct SerializedPackTelemetry {
    pub(crate) has_l2_base: bool,
    pub(crate) result_ids: Vec<[u8; 16]>,
    pub(crate) stats: PackStats,
}

pub fn serialize_pack(pack: &ContextPack, config: &SerializeConfig) -> Vec<u8> {
    serialize_pack_with_tokenizer(pack, config, DEFAULT_CONTEXT_PACK_TOKENIZER)
}

pub fn serialize_pack_with_tokenizer(
    pack: &ContextPack,
    config: &SerializeConfig,
    tokenizer: PackTokenizer,
) -> Vec<u8> {
    let sanitized;
    let pack = if matches!(
        config.format,
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini
    ) {
        sanitized = super::provider_codecs::sanitize_pack(pack);
        &sanitized
    } else {
        pack
    };
    let prepared = prepare_pack(pack, config, config.format == PackFormat::Json, tokenizer);
    serialize_prepared_pack(pack, config, prepared, tokenizer)
}

pub(crate) fn serialize_pack_with_telemetry(
    pack: &ContextPack,
    config: &SerializeConfig,
    tokenizer: PackTokenizer,
) -> (Vec<u8>, SerializedPackTelemetry) {
    let sanitized;
    let pack = if matches!(
        config.format,
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini
    ) {
        sanitized = super::provider_codecs::sanitize_pack(pack);
        &sanitized
    } else {
        pack
    };
    let prepared = prepare_pack(pack, config, config.format == PackFormat::Json, tokenizer);
    let telemetry = serialize_prepared_pack_telemetry(&prepared);
    let bytes = serialize_prepared_pack(pack, config, prepared, tokenizer);
    (bytes, telemetry)
}

/// Apply JSON context-pack field projection plus real-token budget controls
/// while preserving the structured `ContextPack` envelope used by HTTP APIs.
pub fn project_pack_for_json_response(
    mut pack: ContextPack,
    config: &SerializeConfig,
) -> ContextPack {
    project_pack_for_json_response_with_tokenizer(pack, config, DEFAULT_CONTEXT_PACK_TOKENIZER)
}

pub fn project_pack_for_json_response_with_tokenizer(
    mut pack: ContextPack,
    config: &SerializeConfig,
    tokenizer: PackTokenizer,
) -> ContextPack {
    let prepared = prepare_pack(&pack, config, true, tokenizer);
    let stats = prepared.stats.clone();
    pack.l2_base = prepared.l2_base.clone();
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

pub(super) fn serialize_prepared_pack(
    pack: &ContextPack,
    config: &SerializeConfig,
    mut prepared: PreparedPack,
    tokenizer: PackTokenizer,
) -> Vec<u8> {
    let empty =
        prepared.results.is_empty() && prepared.neighbors.is_empty() && prepared.l2_base.is_none();
    let l2_base = prepared.l2_base.clone();
    let mut handles = super::handles::Handles::new(pack, &mut prepared);
    if !matches!(config.format, PackFormat::Json | PackFormat::Toon) {
        handles.rows(&mut prepared.results, config.format != PackFormat::Yaml);
        handles.rows(&mut prepared.neighbors, config.format != PackFormat::Yaml);
    }
    let bytes = match config.format {
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini => {
            super::provider_codecs::serialize_provider(config.format, prepared)
        }
        PackFormat::Json => serialize_json(pack, config, prepared, &mut handles),
        PackFormat::Yaml => serialize_yaml(config, prepared).into_bytes(),
        PackFormat::Toon => serialize_toon(config, prepared, &mut handles).into_bytes(),
        PackFormat::Markdown => serialize_markdown(config, prepared).into_bytes(),
        PackFormat::Plaintext => serialize_plaintext(config, prepared).into_bytes(),
    };
    let bytes = super::l2_prefix::with_l2_prefix(l2_base.as_ref(), config.format, bytes);
    if empty
        && !matches!(
            config.format,
            PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini
        )
        && config.budget > 0
        && tokenizer.count(std::str::from_utf8(&bytes).expect("serialized UTF-8")) > config.budget
    {
        return if config.format == PackFormat::Json {
            b"{}".to_vec()
        } else {
            Vec::new()
        };
    }
    bytes
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
        has_l2_base: prepared.l2_base.is_some(),
        result_ids,
        stats: prepared.stats.clone(),
    }
}

pub fn serialize_assembled_context(bundle: &AssembledContext) -> Vec<u8> {
    serde_json::to_vec(bundle).expect("AssembledContext JSON serialization should not fail")
}

fn serialize_json(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: PreparedPack,
    handles: &mut super::handles::Handles,
) -> Vec<u8> {
    let stats = prepared.stats.clone();
    let mut root = Map::new();

    if prepared.merged {
        for (kind, entities) in prepared.results {
            if entities.is_empty() {
                continue;
            }
            let mut rows = json_rows(&entities, true);
            handles.emitted_rows(&entities, &mut rows);
            root.insert(group_key(kind).to_owned(), Value::Array(rows));
        }
    } else {
        root.insert(
            "results".to_owned(),
            Value::Object(section_object(&prepared.results, true, handles)),
        );
        root.insert(
            "neighbors".to_owned(),
            Value::Object(section_object(&prepared.neighbors, true, handles)),
        );
    }

    if config.include_stats {
        root.insert("stats".to_owned(), json_stats(&stats));
    }
    if let Some(empty) = &pack.empty
        && let Ok(mut value) = serde_json::to_value(empty)
    {
        handles.value(&mut value);
        root.insert("empty".to_owned(), value);
    }

    serde_json::to_vec(&Value::Object(root)).unwrap_or_else(|_| b"{}".to_vec())
}

fn serialize_toon(
    config: &SerializeConfig,
    prepared: PreparedPack,
    handles: &mut super::handles::Handles,
) -> String {
    let mut out = String::new();
    if prepared.merged {
        out.push_str(&encode_toon_section(&prepared.results, handles));
    } else {
        let results = encode_toon_section(&prepared.results, handles);
        let neighbors = encode_toon_section(&prepared.neighbors, handles);

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
