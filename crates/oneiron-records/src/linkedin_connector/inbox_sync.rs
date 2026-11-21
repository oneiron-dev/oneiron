//! Moved from `crates/oneiron/src/linkedin_connector/inbox_sync.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Stable provenance marker persisted beside each seen LinkedIn message row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInInboxSyncProvenanceRow {
    pub schema_version: u64,
    pub source: String,
    pub tier: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    pub thread_id: String,
    pub message_id: String,
    pub surface_event_id: String,
    pub payload_ref: Option<String>,
    pub received_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<u64>,
}
