//! Entry points and per-format dispatch for context-pack serialization.
//!
//! Note the deliberate cycle with [`super::token_budget`]: the serialized-output
//! budget and the token-stats pass both re-encode a prepared pack through
//! [`serialize_prepared_pack`] to measure its real size, so `token_budget` calls
//! back into this module. Measuring after encoding is the contract, not a layering
//! slip.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::serialize::context_entity::ContextEntity;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::FieldProfile;
use crate::serialize::pack_format::PackFormat;
use oneiron_base::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER;
use oneiron_base::tokenizer::PackTokenizer;

use crate::serialize::group_labels::group_key;
use crate::serialize::json_format::json_rows;
use crate::serialize::types::GroupKey;

/// Codec label for deterministic code-run raw output previews.
pub const CODE_RUN_OUTPUT_PREVIEW_CODEC: &str = "utf8-lossy-whitespace-compact-v1";
/// Default character cap for compact code-run raw output previews.
pub const CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS: usize = 256;

/// Stable serializer identity recorded in whole-vault export manifests.
pub const WHOLE_VAULT_EXPORT_SERIALIZER: &str = "oneiron.whole_vault_export";
/// Version of the whole-vault export serializer contract.
pub const WHOLE_VAULT_EXPORT_SERIALIZER_VERSION: u16 = 2;

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
pub struct PreparedEntity {
    pub entity_type: u8,
    pub score: f32,
    pub critical: bool,
    pub source: PreparedEntitySource,
    pub source_id: [u8; 16],
    pub id: String,
    pub fields: Vec<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedEntitySource {
    Result,
    Neighbor,
}

pub type PreparedGroups = Vec<(GroupKey, Vec<PreparedEntity>)>;

pub fn collect_projected_json_rows(
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

pub fn apply_projected_json_rows(
    entities: Vec<ContextEntity>,
    mut projected_rows: HashMap<[u8; 16], Vec<(String, Value)>>,
) -> Vec<ContextEntity> {
    let mut projected: Vec<_> = entities
        .into_iter()
        .filter_map(|mut entity| {
            let fields = projected_rows.remove(entity.id.as_bytes())?;
            if entity.fields.is_some() {
                entity.fields = Some(HashMap::from_iter(fields));
            }
            Some(entity)
        })
        .collect();
    projected.sort_by(|a, b| {
        b.critical
            .cmp(&a.critical)
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.id.cmp(&b.id))
    });
    projected
}

/// Builds the compact text preview stored beside raw code-run output bytes.
///
/// The preview is deterministic and intentionally lossy: invalid UTF-8 is
/// replaced, runs of whitespace collapse to one ASCII space, and the result is
/// capped by `max_chars`. It stops reading at the cap, so a large output costs
/// no more memory than a small one.
#[must_use]
pub fn compressed_code_run_output_preview(raw: &[u8], max_chars: usize) -> (String, bool) {
    if raw.is_empty() || max_chars == 0 {
        return (String::new(), !raw.is_empty());
    }

    // `String::from_utf8_lossy`'s replacement, one chunk at a time.
    let chars = raw.utf8_chunks().flat_map(|chunk| {
        chunk
            .valid()
            .chars()
            .chain((!chunk.invalid().is_empty()).then_some(char::REPLACEMENT_CHARACTER))
    });
    let mut preview = String::new();
    let mut kept = 0_usize;
    // A whitespace run becomes one space only once a later character follows
    // it, so the preview never ends in one.
    let mut space_pending = false;
    let mut previous_was_space = true;
    for ch in chars {
        if ch.is_whitespace() {
            space_pending |= !previous_was_space;
            previous_was_space = true;
            continue;
        }
        for ch in space_pending.then_some(' ').into_iter().chain([ch]) {
            if kept == max_chars {
                return (preview, true);
            }
            preview.push(ch);
            kept += 1;
        }
        space_pending = false;
        previous_was_space = false;
    }

    (preview, false)
}

