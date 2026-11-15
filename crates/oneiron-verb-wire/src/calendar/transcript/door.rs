//! Moved from `crates/oneiron/src/calendar/transcript/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One uploaded UTF-8 transcript. `decoded_text` must match the stored head's
/// bytes exactly; it is not caller-asserted evidence for a different blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptFileDropInput {
    pub source_blob_ref: String,
    pub decoded_text: String,
    pub arrived_at_ms: u64,
    /// Optional meeting to link only after this upload earns a closed SESSION.
    #[serde(default)]
    pub event_ref: Option<String>,
}
