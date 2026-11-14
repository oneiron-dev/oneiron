//! Moved from `crates/oneiron/src/ingest/meeting_audio/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Times always use milliseconds. VAD and diarization use the full-file clock;
/// ASR uses the concatenated pack clock and is mapped by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpeechSpan {
    pub start_ms: u64,
    pub end_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceSpan {
    pub source_start_ms: u64,
    pub source_end_ms: u64,
    pub pack_start_ms: u64,
    pub pack_end_ms: u64,
}

/// The host must return a full-file exclusive track, not an overlapping
/// diarization track. Speaker labels must keep their full-file identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpeakerTrack {
    pub start_ms: u64,
    pub end_ms: u64,
    pub speaker_cluster: String,
}

/// The consent request binds the complete artifact, not only an audio filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkImportBinding {
    /// Opaque vault/owner context supplied by the authenticated authorizer.
    pub vault_scope: String,
    pub source_id: String,
    pub recording_id: String,
    pub artifact_sha256: String,
    pub source_record_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct BulkImportReceipt {
    pub binding: BulkImportBinding,
    pub receipt_ref: String,
}
