//! Ingest source registry and source-local normalization.
//!
//! This module intentionally stops before semantic extraction: sources
//! normalize raw fixture/input records into text-bearing records, but do not
//! mint claim writes.

use serde_json::{Map, Value};

pub const JSONL_TRANSCRIPT_SOURCE_ID: &str = "jsonl-transcript";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngestSourceFormat {
    JsonlTranscript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestSourceConfig {
    pub source_id: &'static str,
    pub label: &'static str,
    pub format: IngestSourceFormat,
    pub writes_claims: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestHarnessConfig {
    pub sources: &'static [IngestSourceConfig],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestBatch {
    pub source_id: &'static str,
    pub records: Vec<NormalizedIngestRecord>,
    pub claims: Vec<NormalizedIngestClaim>,
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
}

pub trait IngestSource: Send + Sync {
    fn config(&self) -> IngestSourceConfig;

    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch>;
}

pub struct IngestSourceRegistry {
    sources: &'static [&'static dyn IngestSource],
}

impl IngestSourceRegistry {
    pub const fn new(sources: &'static [&'static dyn IngestSource]) -> Self {
        Self { sources }
    }

    pub fn sources(&self) -> &'static [&'static dyn IngestSource] {
        self.sources
    }

    pub fn source_configs(&self) -> impl Iterator<Item = IngestSourceConfig> + '_ {
        self.sources.iter().map(|source| source.config())
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.source_configs().map(|config| config.source_id)
    }

    pub fn get(&self, source_id: &str) -> Option<&'static dyn IngestSource> {
        self.sources
            .iter()
            .copied()
            .find(|source| source.config().source_id == source_id)
    }

    pub fn normalize(&self, source_id: &str, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let source = self
            .get(source_id)
            .ok_or_else(|| IngestError::UnknownSource {
                source_id: source_id.to_owned(),
            })?;
        source.normalize(input)
    }
}

pub struct JsonlTranscriptSource;

impl JsonlTranscriptSource {
    pub const CONFIG: IngestSourceConfig = IngestSourceConfig {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        label: "JSONL transcript",
        format: IngestSourceFormat::JsonlTranscript,
        writes_claims: false,
    };
}

impl IngestSource for JsonlTranscriptSource {
    fn config(&self) -> IngestSourceConfig {
        Self::CONFIG
    }

    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let mut records = Vec::new();

        for (index, raw_line) in input.lines().enumerate() {
            let line = index + 1;
            let raw_line = raw_line.trim();
            if raw_line.is_empty() {
                continue;
            }

            let value: Value =
                serde_json::from_str(raw_line).map_err(|err| IngestError::InvalidJson {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    message: err.to_string(),
                })?;
            let object = value.as_object().ok_or(IngestError::JsonLineNotObject {
                source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                line,
            })?;

            records.push(normalize_transcript_object(object, line)?);
        }

        Ok(NormalizedIngestBatch {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            records,
            claims: Vec::new(),
        })
    }
}

static JSONL_TRANSCRIPT_SOURCE: JsonlTranscriptSource = JsonlTranscriptSource;
static INGEST_SOURCES: [&dyn IngestSource; 1] = [&JSONL_TRANSCRIPT_SOURCE];

pub static INGEST_SOURCE_REGISTRY: IngestSourceRegistry =
    IngestSourceRegistry::new(&INGEST_SOURCES);

static KNOWN_HARNESS_SOURCES: [IngestSourceConfig; 1] = [JsonlTranscriptSource::CONFIG];

pub static KNOWN_INGEST_HARNESS_CONFIG: IngestHarnessConfig = IngestHarnessConfig {
    sources: &KNOWN_HARNESS_SOURCES,
};

fn normalize_transcript_object(
    object: &Map<String, Value>,
    line: usize,
) -> IngestResult<NormalizedIngestRecord> {
    let source_record_id =
        required_string_field(object, line, "id", &["id", "message_id", "turn_id"])?.to_owned();
    let text = normalize_space(required_string_field(
        object,
        line,
        "text",
        &["text", "content"],
    )?);
    if text.is_empty() {
        return Err(IngestError::EmptyText {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            line,
        });
    }

    Ok(NormalizedIngestRecord {
        source_record_id,
        thread_id: optional_normalized_string_field(
            object,
            line,
            "thread_id",
            &["thread_id", "conversation_id", "session_id"],
        )?,
        speaker: optional_normalized_string_field(
            object,
            line,
            "speaker",
            &["speaker", "role", "author"],
        )?
        .map(|speaker| speaker.to_ascii_lowercase()),
        occurred_at: optional_u64_field(object, line, "occurred_at", &["occurred_at", "ts"])?,
        text,
    })
}

fn required_string_field<'a>(
    object: &'a Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<&'a str> {
    optional_string_field(object, line, canonical, aliases)?.ok_or(IngestError::MissingField {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        line,
        field: canonical,
    })
}

fn optional_normalized_string_field(
    object: &Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<String>> {
    Ok(optional_string_field(object, line, canonical, aliases)?
        .map(normalize_space)
        .filter(|field| !field.is_empty()))
}

fn optional_string_field<'a>(
    object: &'a Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<&'a str>> {
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            return value
                .as_str()
                .map(Some)
                .ok_or(IngestError::InvalidStringField {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    field: canonical,
                });
        }
    }
    Ok(None)
}

fn optional_u64_field(
    object: &Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<u64>> {
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            return value
                .as_u64()
                .map(Some)
                .ok_or(IngestError::InvalidU64Field {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    field: canonical,
                });
        }
    }
    Ok(None)
}

fn normalize_space(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut saw_space = false;

    for ch in input.chars() {
        if ch.is_whitespace() {
            saw_space = true;
        } else {
            if saw_space && !out.is_empty() {
                out.push(' ');
            }
            out.push(ch);
            saw_space = false;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_TRANSCRIPT_FIXTURE: &str =
        include_str!("../tests/fixtures/ingest/minimal_transcript.jsonl");

    #[test]
    fn ingest_registry_equals_known_harness_config() {
        let registry_configs = INGEST_SOURCE_REGISTRY.source_configs().collect::<Vec<_>>();

        assert_eq!(
            registry_configs.as_slice(),
            KNOWN_INGEST_HARNESS_CONFIG.sources
        );
        assert!(registry_configs.iter().all(|config| !config.writes_claims));
    }

    #[test]
    fn ingest_jsonl_transcript_fixture_normalizes_records_without_claims() {
        let batch = INGEST_SOURCE_REGISTRY
            .normalize(JSONL_TRANSCRIPT_SOURCE_ID, MINIMAL_TRANSCRIPT_FIXTURE)
            .expect("fixture normalizes");

        assert_eq!(batch.source_id, JSONL_TRANSCRIPT_SOURCE_ID);
        assert_eq!(batch.records.len(), 2);
        assert!(
            batch.claims.is_empty(),
            "source normalization must not write claims"
        );

        assert_eq!(
            batch.records[0],
            NormalizedIngestRecord {
                source_record_id: "turn-001".to_owned(),
                thread_id: Some("dream-session-001".to_owned()),
                speaker: Some("dreamer".to_owned()),
                occurred_at: Some(1_773_532_800),
                text: "I saw a blue door at the end of a long hallway.".to_owned(),
            }
        );
        assert_eq!(
            batch.records[1],
            NormalizedIngestRecord {
                source_record_id: "turn-002".to_owned(),
                thread_id: Some("dream-session-001".to_owned()),
                speaker: Some("assistant".to_owned()),
                occurred_at: Some(1_773_532_806),
                text: "What did the door feel like?".to_owned(),
            }
        );
    }
}
