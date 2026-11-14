//! Moved from `crates/oneiron/src/memory/archive_delete_wire.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Explicit archived records to preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeletePreviewRequest {
    /// 32-hex entity ids of records the cleanup archived.
    pub targets: Vec<String>,
}

/// What a preview read of one archived record, which a confirm item may
/// bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteExpectation {
    /// 64-hex BLAKE3 hash of the record's retained bytes.
    pub record_hash: String,
    /// Hex of the record's exact archive marker bytes.
    pub archive_marker: String,
}

/// One archived record to delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteItem {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// The record as a preview read it; absent, the current record is
    /// deleted while it is still a cleanup archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<ArchiveDeleteExpectation>,
}

/// Explicit archived records to delete, each once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteConfirmRequest {
    /// The records; an id named twice is deleted once, under its first item.
    pub items: Vec<ArchiveDeleteItem>,
}

/// One record's typed refusal or failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteError {
    /// One of the `MEMORY_CODE_*` strings.
    pub code: String,
    /// What refused or failed; a refusal's own code leads it.
    pub message: String,
    /// Remediation hints.
    pub suggestions: Vec<String>,
}

/// What deleting one previewed record would remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewRow {
    /// The record's retained bytes, not a filesystem-space estimate.
    pub record_bytes: u64,
    /// What a confirm item may bind.
    pub expected: ArchiveDeleteExpectation,
}

/// One target's preview: its row, or why it may not be deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ArchiveDeletePreviewOutcome {
    /// The record is a cleanup archive this caller may delete.
    Previewed(ArchiveDeletePreviewRow),
    /// The record is refused, alone.
    Refused {
        /// Why, typed.
        error: ArchiveDeleteError,
    },
}

/// One target's preview entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewEntry {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// Its row or its refusal.
    pub result: ArchiveDeletePreviewOutcome,
}

/// The impact preview: one entry per distinct target, in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewView {
    /// Every distinct target's entry.
    pub entries: Vec<ArchiveDeletePreviewEntry>,
    /// The retained bytes of every previewed record.
    pub record_bytes: u64,
}

/// One deleted record's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteReceiptView {
    /// Whether the record existed before the delete.
    pub existed: bool,
    /// Always `user_hard_delete`.
    pub reason: String,
    /// The redaction audit receipt (`redaction:<hex>`), when one was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// The role the delete was admitted under: owner, admin, member or
    /// agent.
    pub role: String,
    /// The membership grant or agent Grant that admitted it, as evidence;
    /// absent for an owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
}

/// One target's delete: its receipt, or why it was not deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ArchiveDeleteConfirmOutcome {
    /// The record was deleted.
    Deleted(ArchiveDeleteReceiptView),
    /// The record was refused or its delete failed, alone.
    Refused {
        /// Why, typed.
        error: ArchiveDeleteError,
    },
}

/// One target's confirm entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteConfirmEntry {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// Its receipt or its error.
    pub result: ArchiveDeleteConfirmOutcome,
}

/// The confirm's answer: one entry per distinct target, in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteBatchResult {
    /// Every distinct target's entry.
    pub entries: Vec<ArchiveDeleteConfirmEntry>,
}
