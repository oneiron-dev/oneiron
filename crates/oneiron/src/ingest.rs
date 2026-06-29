//! Ingest source registry and source-local normalization.
//!
//! This module intentionally stops before semantic extraction: sources
//! normalize raw fixture/input records into text-bearing records, but do not
//! mint claim writes.

use serde_json::{Map, Value};

use crate::claim::{ClaimApprovalStatus, ClaimSource};

pub const JSONL_TRANSCRIPT_SOURCE_ID: &str = "jsonl-transcript";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngestSourceFormat {
    JsonlTranscript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestTrustCeiling {
    pub claim_source: ClaimSource,
    pub max_auto_sensitivity: Option<u8>,
    pub receipted: bool,
    pub warned: bool,
}

impl IngestTrustCeiling {
    #[must_use]
    pub fn permits_auto(self, sensitivity: Option<u8>) -> bool {
        let Some(sensitivity) = sensitivity else {
            return false;
        };
        let Some(max_auto_sensitivity) = self.max_auto_sensitivity else {
            return false;
        };
        if sensitivity > max_auto_sensitivity {
            return false;
        }
        if self.claim_source.requires_explicit_auto_permit() && (!self.receipted || !self.warned) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestSourceConfig {
    pub source_id: &'static str,
    pub label: &'static str,
    pub format: IngestSourceFormat,
    pub writes_claims: bool,
    pub trust_ceiling: IngestTrustCeiling,
    pub default_admission: ClaimApprovalStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestHarnessConfig {
    registry: &'static IngestSourceRegistry,
}

impl IngestHarnessConfig {
    pub const fn from_registry(registry: &'static IngestSourceRegistry) -> Self {
        Self { registry }
    }

    #[must_use]
    pub const fn registry(&self) -> &'static IngestSourceRegistry {
        self.registry
    }

    pub fn source_configs(&self) -> impl Iterator<Item = IngestSourceConfig> + '_ {
        self.registry.source_configs()
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.registry.source_ids()
    }

    #[must_use]
    pub fn get_config(&self, source_id: &str) -> Option<IngestSourceConfig> {
        self.registry.get_config(source_id)
    }
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
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch>;
}

#[derive(Clone, Copy)]
pub struct IngestSourceRegistration {
    config: IngestSourceConfig,
    source: &'static dyn IngestSource,
}

impl IngestSourceRegistration {
    pub const fn new(config: IngestSourceConfig, source: &'static dyn IngestSource) -> Self {
        Self { config, source }
    }

    #[must_use]
    pub const fn config(&self) -> IngestSourceConfig {
        self.config
    }

    #[must_use]
    pub fn source(&self) -> &'static dyn IngestSource {
        self.source
    }
}

impl std::fmt::Debug for IngestSourceRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestSourceRegistration")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IngestSourceRegistry {
    entries: &'static [IngestSourceRegistration],
}

impl IngestSourceRegistry {
    pub const fn new(entries: &'static [IngestSourceRegistration]) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &'static [IngestSourceRegistration] {
        self.entries
    }

    pub fn sources(&self) -> impl Iterator<Item = &'static dyn IngestSource> + '_ {
        self.entries.iter().map(IngestSourceRegistration::source)
    }

    pub fn source_configs(&self) -> impl Iterator<Item = IngestSourceConfig> + '_ {
        self.entries.iter().map(IngestSourceRegistration::config)
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.source_configs().map(|config| config.source_id)
    }

    #[must_use]
    pub fn get_config(&self, source_id: &str) -> Option<IngestSourceConfig> {
        self.entries
            .iter()
            .find(|entry| entry.config.source_id == source_id)
            .map(IngestSourceRegistration::config)
    }

    pub fn get(&self, source_id: &str) -> Option<&'static dyn IngestSource> {
        self.entries
            .iter()
            .find(|entry| entry.config.source_id == source_id)
            .map(IngestSourceRegistration::source)
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

impl IngestSource for JsonlTranscriptSource {
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
static INGEST_SOURCE_ENTRIES: [IngestSourceRegistration; 1] = [IngestSourceRegistration::new(
    IngestSourceConfig {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        label: "JSONL transcript",
        format: IngestSourceFormat::JsonlTranscript,
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    },
    &JSONL_TRANSCRIPT_SOURCE,
)];

pub static INGEST_SOURCE_REGISTRY: IngestSourceRegistry =
    IngestSourceRegistry::new(&INGEST_SOURCE_ENTRIES);

pub static KNOWN_INGEST_HARNESS_CONFIG: IngestHarnessConfig =
    IngestHarnessConfig::from_registry(&INGEST_SOURCE_REGISTRY);

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
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            return value.as_str().ok_or(IngestError::InvalidStringField {
                source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                line,
                field: canonical,
            });
        }
    }
    Err(IngestError::MissingField {
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
            if value.is_null() {
                continue;
            }
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
            if value.is_null() {
                continue;
            }
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
    const NULL_OPTIONAL_METADATA_FIXTURE: &str =
        include_str!("../tests/fixtures/ingest/null_optional_metadata.jsonl");

    fn expected_jsonl_transcript_config() -> IngestSourceConfig {
        IngestSourceConfig {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            label: "JSONL transcript",
            format: IngestSourceFormat::JsonlTranscript,
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        }
    }

    #[test]
    fn ingest_registry_equals_known_harness_config() {
        let registry_configs = INGEST_SOURCE_REGISTRY.source_configs().collect::<Vec<_>>();
        let harness_configs = KNOWN_INGEST_HARNESS_CONFIG
            .source_configs()
            .collect::<Vec<_>>();

        assert!(std::ptr::eq(
            KNOWN_INGEST_HARNESS_CONFIG.registry(),
            &INGEST_SOURCE_REGISTRY
        ));
        assert_eq!(registry_configs, harness_configs);
        assert_eq!(registry_configs, [expected_jsonl_transcript_config()]);
    }

    #[test]
    fn jsonl_transcript_policy_defaults_to_proposed_and_fails_closed_for_auto() {
        let config = INGEST_SOURCE_REGISTRY
            .get_config(JSONL_TRANSCRIPT_SOURCE_ID)
            .expect("jsonl source config");

        assert_eq!(config, expected_jsonl_transcript_config());
        assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
        assert_eq!(config.trust_ceiling.max_auto_sensitivity, None);
        assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
        assert!(!config.trust_ceiling.permits_auto(Some(0)));
        assert!(!config.trust_ceiling.permits_auto(None));
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

    #[test]
    fn ingest_jsonl_transcript_optional_null_metadata_is_absent() {
        let batch = INGEST_SOURCE_REGISTRY
            .normalize(JSONL_TRANSCRIPT_SOURCE_ID, NULL_OPTIONAL_METADATA_FIXTURE)
            .expect("fixture normalizes");

        assert_eq!(
            batch.records.as_slice(),
            [NormalizedIngestRecord {
                source_record_id: "turn-null".to_owned(),
                thread_id: None,
                speaker: None,
                occurred_at: None,
                text: "Null optional metadata is omitted.".to_owned(),
            }]
        );
    }

    #[test]
    fn ingest_jsonl_transcript_required_null_field_is_invalid() {
        let err = INGEST_SOURCE_REGISTRY
            .normalize(
                JSONL_TRANSCRIPT_SOURCE_ID,
                r#"{"id":null,"text":"required id is null"}"#,
            )
            .expect_err("required null field must fail");

        assert_eq!(
            err,
            IngestError::InvalidStringField {
                source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                line: 1,
                field: "id",
            }
        );
    }
}
