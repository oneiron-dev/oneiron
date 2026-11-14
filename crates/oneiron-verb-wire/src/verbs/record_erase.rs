//! Moved from `crates/oneiron/src/verbs/record_erase.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.records.erase_preview`'s input: the record to erase.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseRequest {
    pub record: EntityId,
}

/// `vault.records.erase_confirm`'s input: the record, the digest of the
/// preview the caller confirms, and whether every other record holding the
/// same bytes goes too.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseConfirmRequest {
    pub record: EntityId,
    pub preview_digest: String,
    #[serde(default)]
    pub also_same_bytes: bool,
}
