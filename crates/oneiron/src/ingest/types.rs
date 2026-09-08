//! Normalized ingest types: batch, record, claim, and note plus the ingest result and error.

use serde_json::Value;

use super::NormalizedIngestEntity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestBatch {
    pub source_id: &'static str,
    pub records: Vec<NormalizedIngestRecord>,
    pub claims: Vec<NormalizedIngestClaim>,
    /// Text-bearing assets normalized by binary ingest sources.
    pub entities: Vec<NormalizedIngestEntity>,
    /// A whole-batch note the producer supplied for consumers that cannot land
    /// `records` as individual entities. Present whenever the producer supplied
    /// one; choosing it over the records is the consumer's decision, not this
    /// layer's.
    pub note_fallback: Option<NormalizedIngestNote>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestNote {
    pub source_record_id: String,
    pub occurred_at: Option<u64>,
    pub title: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestRecord {
    pub source_record_id: String,
    pub thread_id: Option<String>,
    pub speaker: Option<String>,
    pub occurred_at: Option<u64>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestClaim {
    pub source_record_id: String,
    pub predicate: String,
    pub value: Value,
}

pub type IngestResult<T> = std::result::Result<T, IngestError>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngestError {
    #[error("unknown ingest source `{source_id}`")]
    UnknownSource { source_id: String },

    #[error("ingest source does not support this input type")]
    UnsupportedInput,

    #[error("ingest source `{source_id}` line {line} is not a JSON object")]
    JsonLineNotObject {
        source_id: &'static str,
        line: usize,
    },

    #[error("ingest source `{source_id}` line {line} has invalid JSON: {message}")]
    InvalidJson {
        source_id: &'static str,
        line: usize,
        message: String,
    },

    #[error("ingest source `{source_id}` line {line} is missing required field `{field}`")]
    MissingField {
        source_id: &'static str,
        line: usize,
        field: &'static str,
    },

    #[error("ingest source `{source_id}` line {line} field `{field}` must be a string")]
    InvalidStringField {
        source_id: &'static str,
        line: usize,
        field: &'static str,
    },

    #[error("ingest source `{source_id}` line {line} field `{field}` must be an unsigned integer")]
    InvalidU64Field {
        source_id: &'static str,
        line: usize,
        field: &'static str,
    },

    #[error("ingest source `{source_id}` line {line} normalizes to empty text")]
    EmptyText {
        source_id: &'static str,
        line: usize,
    },

    // The meeting-transcript artifact is one document rather than a line
    // stream, so its failures name the offending path or id instead of a line.
    #[error("ingest source `{source_id}` document has invalid JSON: {message}")]
    InvalidDocument {
        source_id: &'static str,
        message: String,
    },

    #[error("ingest source `{source_id}` local OCR is unavailable: {message}")]
    OcrUnavailable {
        source_id: &'static str,
        message: String,
    },

    #[error("ingest source `{source_id}` expects schema `{expected}`, got `{found}`")]
    UnsupportedSchema {
        source_id: &'static str,
        expected: &'static str,
        found: String,
    },

    #[error("ingest source `{source_id}` document field `{path}` is missing or malformed")]
    InvalidDocumentField {
        source_id: &'static str,
        path: String,
    },

    #[error("ingest source `{source_id}` document has a duplicate `{kind}` id `{id}`")]
    DuplicateId {
        source_id: &'static str,
        kind: &'static str,
        id: String,
    },

    #[error(
        "ingest source `{source_id}` turn `{turn_id}` has non-monotone or out-of-bounds timestamps"
    )]
    InvalidTurnTimestamps {
        source_id: &'static str,
        turn_id: String,
    },

    #[error("ingest source `{source_id}` turn `{turn_id}` references unknown word `{word_id}`")]
    UnknownWordReference {
        source_id: &'static str,
        turn_id: String,
        word_id: String,
    },

    #[error(
        "ingest source `{source_id}` turn `{turn_id}` timestamp overflows `occurred_at` arithmetic"
    )]
    TimestampOverflow {
        source_id: &'static str,
        turn_id: String,
    },

    #[error("ingest source `{source_id}` document is not a complete ICS feed: {message}")]
    InvalidIcsDocument {
        source_id: &'static str,
        message: String,
    },
}
