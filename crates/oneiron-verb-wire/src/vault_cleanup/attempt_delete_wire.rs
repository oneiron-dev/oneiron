//! Moved from `crates/oneiron/src/vault_cleanup/attempt_delete_wire.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::attempt_archive_mark::CleanupMark;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_state::AttemptState;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// One explicitly selected completed-attempt archive. These fields grant no authority.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptArchiveDeletePreviewRequest {
    pub attempt: String,
}

/// The exact queue bytes and cleanup archive mark observed by preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptArchiveDeleteExpectation {
    pub record_hash: String,
    pub archive_marker: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttemptArchiveDeletePreviewView {
    pub attempt: String,
    pub record_bytes: u64,
    pub expected: AttemptArchiveDeleteExpectation,
}

/// Confirm names the preview's bytes, not a reusable authorization token.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptArchiveDeleteConfirmRequest {
    pub attempt: String,
    pub expected: AttemptArchiveDeleteExpectation,
}

/// A deletion that committed, with the durable run-history receipt's address.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttemptArchiveDeleteReceiptView {
    pub attempt: String,
    pub deleted_by: String,
    pub deleted_at: u64,
    pub run_id: Option<String>,
    pub receipt_ref: String,
    pub role: String,
    pub grant_ref: Option<String>,
}
