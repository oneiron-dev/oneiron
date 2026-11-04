//! Context-pack serialization.
//!
//! `pack_entry` holds the entry points and the per-format dispatch;
//! `pack_preparation`, `item_budget` and `token_budget` shape and budget a pack
//! before it is written; `json_format`, `toon_format`, `markdown_plaintext_format`
//! and `yaml_format` are the writers.

pub(crate) mod access_grant_fields;
mod credential_nulling;
mod value_json;
pub(crate) use value_json::msgpack_value_projection;
pub use value_json::{msgpack_value_from_json, msgpack_value_to_json};
pub mod context_entity;
pub mod empty_context;
mod field_profile_table;
pub(crate) mod grant_fields;
mod group_labels;
mod handles;
mod item_budget;
mod json_format;
mod l2_prefix;
mod markdown_plaintext_format;
pub mod outbound_grant_fields;
pub mod pack_accounting;
mod pack_entry;
pub mod pack_format;
mod pack_preparation;
pub(crate) mod persona_export_fields;
mod provider_codecs;
mod token_budget;
mod toon_format;
mod types;
mod yaml_format;

#[cfg(test)]
mod tests;
// The L2 producer must render the same safe value projection as ranked rows.
pub(crate) use credential_nulling::{null_credentials, null_document_tree_row};
pub(crate) use provider_codecs::scrub as scrub_provider_credential;

pub use pack_entry::{
    CODE_RUN_OUTPUT_PREVIEW_CODEC, CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS, SerializeConfig,
    WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION,
    compressed_code_run_output_preview, project_pack_for_json_response,
    project_pack_for_json_response_with_tokenizer, serialize_assembled_context, serialize_pack,
    serialize_pack_with_tokenizer,
};
// Reached only from `commitment`'s tests today; the re-export keeps the historical
// `crate::serialize::` path resolvable for production callers.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use pack_entry::{SerializedPackTelemetry, serialize_pack_with_telemetry};

pub(crate) use oneiron_contracts::serialize::entity_ref;
mod export_format;
pub use export_format::{EXPORT_TARGET_ARCHIVE, EXPORT_TARGET_OKF};
mod export_value;
mod okf_bundle;
mod vault_archive;
mod vault_document;
pub use export_value::{ExportBody, ExportBodyFile, ExportValue};
pub(crate) use export_value::{attaches_as_file, attaches_as_file_read};
pub(crate) use vault_document::{DocumentTail, DocumentWriter};

mod source_tree;
pub(crate) use source_tree::export_source_tree;

mod vault_bundles;

pub(crate) use vault_bundles::agent_bundle;
#[cfg(test)]
pub(crate) use vault_bundles::populate_agent_bundles;

mod pack_archive;
pub use pack_archive::ExportPackInstance;

mod hub_source_archive;
pub use hub_source_archive::ExportHubSource;

mod export_actor_references;

pub(crate) mod person_identity;
