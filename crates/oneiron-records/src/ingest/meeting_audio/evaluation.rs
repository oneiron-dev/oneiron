//! Moved from `crates/oneiron/src/ingest/meeting_audio/evaluation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

/// One E1 arm: a candidate model id plus its exact per-language WER counts.
/// Keys are opaque language tags from the corpus manifest; the engine never
/// invents an arm for a language the corpus did not score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E1Arm {
    pub model_id: String,
    pub model_revision: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub wer_by_lang: HashMap<String, WerCountsSerde>,
}

/// Exact per-language WER counts in receipt form. Integer counts only; a
/// float WER ratio is not accepted because rounding hides the arm sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WerCountsSerde {
    pub substitutions: u64,
    pub deletions: u64,
    pub insertions: u64,
    pub reference_len: u64,
}

/// One labelled E3 cohort file: source audio hash, reference transcript hash,
/// and the consent record the host checked before scoring. The engine binds
/// hashes; consent itself stays a host-side record referenced, never attested,
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortFile {
    pub file_id: String,
    pub audio_sha256: String,
    pub reference_sha256: String,
    pub consent_ref: String,
}

pub fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
