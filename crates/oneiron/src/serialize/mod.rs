//! Context-pack serialization.
//!
//! `pack_entry` holds the entry points and the per-format dispatch;
//! `pack_preparation`, `item_budget` and `token_budget` shape and budget a pack
//! before it is written; `json_format`, `toon_format`, `markdown_plaintext_format`
//! and `yaml_format` are the writers.

pub(crate) use oneiron_store::serialize::access_grant_fields;
mod credential_nulling;
pub use oneiron_store::serialize::context_entity;
pub use oneiron_store::serialize::empty_context;
use oneiron_store::serialize::field_profile_table;
pub(crate) use oneiron_store::serialize::grant_fields;
use oneiron_store::serialize::group_labels;
use oneiron_store::serialize::value_json;
pub(crate) use value_json::msgpack_value_projection;
pub use value_json::{msgpack_value_from_json, msgpack_value_to_json};
mod handles;
mod item_budget;
mod json_format;
use oneiron_store::serialize::l2_prefix;
mod markdown_plaintext_format;
pub use oneiron_store::serialize::outbound_grant_fields;
pub mod pack_accounting;
mod pack_entry;
pub use oneiron_store::serialize::pack_format;
mod pack_preparation;
pub(crate) use oneiron_store::serialize::persona_export_fields;
mod provider_codecs;
mod token_budget;
mod toon_format;
use oneiron_store::serialize::types;
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

pub use export_format::{EXPORT_TARGET_ARCHIVE, EXPORT_TARGET_OKF};
pub(crate) use oneiron_contracts::serialize::entity_ref;
use oneiron_store::serialize::export_format;
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

pub(crate) use oneiron_store::serialize::person_identity;
