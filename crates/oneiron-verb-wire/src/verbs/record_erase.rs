//! Moved from `crates/oneiron/src/verbs/record_erase.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.records.erase_confirm`'s input: the record, the confirm the shared
/// preview returned for this call, and whether every other record holding
/// the same bytes goes too.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseConfirmRequest {
    pub record: EntityId,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
    #[serde(default)]
    pub also_same_bytes: bool,
    /// An asker's approved check-in for this erase, 32 hex
    /// (`record_erase_effect_digest`): the Owner applies it on their own
    /// proof, and the outcome names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}
