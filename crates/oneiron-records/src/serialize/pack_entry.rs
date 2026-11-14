//! Moved from `crates/oneiron/src/serialize/pack_entry.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::serialize::pack_entry::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS;
use serde_json::Map;
use serde_json::Value;
use std::collections::HashMap;

/// Stable serializer identity recorded in whole-vault export manifests.
pub const WHOLE_VAULT_EXPORT_SERIALIZER: &str = "oneiron.whole_vault_export";

/// Version of the whole-vault export serializer contract.
pub const WHOLE_VAULT_EXPORT_SERIALIZER_VERSION: u16 = 2;
