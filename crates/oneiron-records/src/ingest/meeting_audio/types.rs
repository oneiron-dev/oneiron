//! Moved from `crates/oneiron/src/ingest/meeting_audio/types.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::ingest::meeting_audio::types::BulkImportBinding;
pub use oneiron_verb_wire::ingest::meeting_audio::types::BulkImportReceipt;
pub use oneiron_verb_wire::ingest::meeting_audio::types::SourceSpan;
pub use oneiron_verb_wire::ingest::meeting_audio::types::SpeakerTrack;
pub use oneiron_verb_wire::ingest::meeting_audio::types::SpeechSpan;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpeechPack {
    pub pack_id: String,
    pub speech_ms: u64,
    pub audio_ms: u64,
    pub oversize_no_boundary: bool,
    pub source_spans: Vec<SourceSpan>,
}

/// Host-reported execution mode, not an engine attestation. Fixture mode must
/// never be cited as an E1/E3 result; measured mode still needs external receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceExecution {
    Fixture,
    Measured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InferenceProvenance {
    /// Unique across the VAD, ASR and diarization calls of one run.
    pub invocation_id: String,
    pub model_id: String,
    pub input_sha256: String,
    pub execution: InferenceExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrRole {
    Asr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingTier {
    Local,
    HomeFleet,
    Hosted,
}

/// E1 evidence belongs to the host. A reference alone is never an engine claim
/// that a bake-off ran or that its preferred model won.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum BatchDefault {
    Provisional {
        model_id: String,
    },
    MeasuredE1 {
        model_id: String,
        evidence_ref: String,
    },
}

impl BatchDefault {
    pub fn model_id(&self) -> &str {
        match self {
            Self::Provisional { model_id } | Self::MeasuredE1 { model_id, .. } => model_id,
        }
    }
}

/// Host-supplied cleanup policy; no lexical correction is admitted without a
/// language rule, an explicitly allowed source/target pair and an acoustic
/// candidate from the same ASR pack. Unknown languages fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupPolicy {
    pub language_rules: BTreeMap<String, LanguageCorrectionRules>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageCorrectionRules {
    pub protected_tokens: Vec<String>,
    pub protected_suffixes: Vec<String>,
    pub allowed_pairs: Vec<AllowedWordCorrection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedWordCorrection {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsrRoute {
    pub role: AsrRole,
    pub model_id: String,
    pub tier: ProcessingTier,
    /// OF-133 host route receipt, including any tier fallback. A different
    /// model requires an explicit batch-default change, never silent drift.
    pub route_receipt_ref: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TranscriptWord {
    pub word_id: String,
    pub pack_id: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub confidence: Option<f64>,
    pub speaker_cluster: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TranscriptTurn {
    pub turn_id: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub source_word_ids: Vec<String>,
    pub speaker_cluster: String,
}
