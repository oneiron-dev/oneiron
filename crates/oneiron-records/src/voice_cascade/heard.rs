//! Moved from `crates/oneiron/src/voice_cascade/heard.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the person heard of one generation, by utterance, kept apart from
/// the text it generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeardPlayback {
    /// The host's correlation ref for the session.
    pub session_ref: String,
    /// The generation's epoch value.
    pub generation: u64,
    /// Each sentence handed to speech, in the order the TTS seam took it.
    pub utterances: Vec<HeardUtterance>,
    /// What the played counts rest on.
    pub basis: HeardBasis,
}

/// One TTS submission of a generation: its text, its audio and how much of
/// the audio played.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeardUtterance {
    /// The submission's number in its generation, from 0: the utterance key.
    pub submission: u64,
    /// The text handed to speech, whole.
    pub text: String,
    /// The audio's rate; 0 when no audio came back for it.
    pub sample_rate: u32,
    /// The audio's length in samples; 0 when no audio came back for it.
    pub samples: u64,
    /// How many of those samples played.
    pub played_samples: u64,
    pub coverage: HeardCoverage,
    /// What the person heard of `text`: all of it when the coverage is
    /// full, nothing when unplayed, and for a part-played utterance the
    /// prefix its validated alignment places at the played count, or `None`
    /// when it has no alignment.
    pub heard_text: Option<String>,
}

/// How much of an utterance's audio played.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeardCoverage {
    Full,
    Partial,
    Unplayed,
}

/// What a record's played counts rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeardBasis {
    /// The client's acknowledgement named the samples it played.
    ClientReport,
    /// The client named none: the counts are the samples the server queued
    /// to it, an upper bound on what played.
    SentUpperBound,
}
