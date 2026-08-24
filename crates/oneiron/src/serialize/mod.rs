//! Context-pack serialization.
//!
//! `pack_entry` holds the entry points and the per-format dispatch;
//! `pack_preparation`, `item_budget` and `token_budget` shape and budget a pack
//! before it is written; `json_format`, `toon_format`, `markdown_plaintext_format`
//! and `yaml_format` are the writers.

mod field_profile_table;
mod group_labels;
mod item_budget;
mod json_format;
mod markdown_plaintext_format;
mod pack_entry;
mod pack_preparation;
mod token_budget;
mod toon_format;
mod types;
mod yaml_format;

#[cfg(test)]
mod tests;

pub use pack_entry::{
    CODE_RUN_OUTPUT_PREVIEW_CODEC, CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS, SerializeConfig,
    WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION,
    compressed_code_run_output_preview, project_pack_for_json_response, serialize_pack,
    serialize_resume_bundle,
};
// Reached only from `commitment`'s tests today; the re-export keeps the historical
// `crate::serialize::` path resolvable for production callers.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use item_budget::is_critical_claim_predicate;
pub(crate) use pack_entry::{SerializedPackTelemetry, serialize_pack_with_telemetry};
