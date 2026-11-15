//! Moved from `crates/oneiron/src/ingest/meeting_audio/recorded_evaluation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceDocument {
    pub file_id: String,
    pub json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordCluster {
    pub word_id: String,
    pub cluster: String,
}

/// Tokenization and word correspondence are corpus data, not guessed by the scorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelledReference {
    pub language: String,
    pub tokenizer: String,
    pub tokens: Vec<String>,
    pub speakers: Vec<WordCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedFile {
    pub file_id: String,
    pub tokens: Vec<String>,
    pub speakers: Vec<WordCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedArm {
    pub model_id: String,
    pub model_revision: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub files: Vec<RecordedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeakerScore {
    pub correct: u64,
    pub wrong_speaker: u64,
    pub missing_words: u64,
    pub extra_words: u64,
}
