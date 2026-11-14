//! Moved from `crates/oneiron/src/calendar/transcript.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::calendar::transcript::TranscriptIngestOutcome;
pub use oneiron_verb_wire::calendar::transcript::door::TranscriptFileDropInput;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTranscriptTurn {
    pub ordinal: u32,
    pub speaker_label: Option<String>,
    pub claimed_start_ms: Option<u64>,
    pub claimed_end_ms: Option<u64>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTranscript {
    pub claimed_started_ms: Option<u64>,
    pub claimed_ended_ms: Option<u64>,
    pub turns: Vec<ParsedTranscriptTurn>,
}
