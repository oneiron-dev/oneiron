//! Moved from `crates/oneiron/src/voice_cascade/protocol.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// ONE-1805 normalized token fields. Times and confidence are provider metadata,
/// never turn authority or evidence of identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsrToken {
    pub text: String,
    pub is_final: bool,
    pub start_ms: Option<f64>,
    pub end_ms: Option<f64>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrEventKind {
    Partial,
    Final,
    Endpoint,
    Error,
    Closed,
}

/// Ordered refs only: no raw entity bodies, vectors or retrieval score scale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalContext {
    pub result_refs: Vec<String>,
    pub promoted: bool,
    pub run_id: Option<String>,
    /// The session's call-mode deadline cut these results short: they are
    /// the best that were ready, not a finished pass.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}
