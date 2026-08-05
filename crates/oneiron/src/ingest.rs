//! Ingest source registry and source-local normalization.
//!
//! Source normalization stops before semantic extraction: sources normalize
//! raw fixture/input records into text-bearing records. Imported evidence can
//! only mint claim writes through an explicit admission helper that requires
//! entity resolution and routes through the normal Gate-backed candidate path.

use rmpv::Value as MsgpackValue;
use serde_json::{Map, Value};

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;

pub const JSONL_TRANSCRIPT_SOURCE_ID: &str = "jsonl-transcript";
pub const MEETING_TRANSCRIPT_SOURCE_ID: &str = "meeting-transcript";

/// Schema version this build of `MeetingTranscriptSource` accepts.
pub const MEETING_TRANSCRIPT_SCHEMA_V1: &str = "oneiron.meeting_transcript.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngestSourceFormat {
    JsonlTranscript,
    MeetingTranscriptV1,
}

/// The ARCH-0027 adapter skill a source's records came from.
///
/// A built-in source is compiled-in code, not a runtime SKILL entity: this
/// descriptor is the parity authority for what produced the input, and it
/// never participates in SKILL lifecycle or hub machinery. Sources with no
/// adapter (records handed straight to the engine) carry `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestAdapterSkillRef {
    pub skill_id: &'static str,
    pub version: &'static str,
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
    pub adapter_skill: Option<IngestAdapterSkillRef>,
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

/// Explicit entity-resolution result required before imported evidence can
/// become a candidate claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedEvidenceEntityResolution {
    pub subject: EntityId,
}

impl ImportedEvidenceEntityResolution {
    #[must_use]
    pub const fn subject(subject: EntityId) -> Self {
        Self { subject }
    }
}

/// Write metadata for admitting one normalized imported evidence claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedEvidenceAdmission {
    pub source_id: String,
    pub claim_id: EntityId,
    pub entity_resolution: ImportedEvidenceEntityResolution,
    pub actor: WriteActor,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub approval: ClaimApprovalStatus,
}

impl ImportedEvidenceAdmission {
    /// Creates the default imported-evidence admission state: proposed review,
    /// not an automatically confirmed claim.
    #[must_use]
    pub fn proposed(
        source_id: impl Into<String>,
        claim_id: EntityId,
        entity_resolution: ImportedEvidenceEntityResolution,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            claim_id,
            entity_resolution,
            actor,
            occurred,
            learned_at,
            approval: ClaimApprovalStatus::Proposed,
        }
    }

    /// Overrides the admission approval when a caller has an explicit
    /// higher-trust import policy. The Gate still decides before persistence.
    #[must_use]
    pub const fn with_approval(mut self, approval: ClaimApprovalStatus) -> Self {
        self.approval = approval;
        self
    }
}

/// Admits imported evidence as a claim candidate after explicit entity
/// resolution and before persistence through the normal Gate write path.
///
/// # Errors
///
/// Returns the underlying claim-candidate write error. Gate/source-trust
/// denial and missing actor or subject entities abort the batch, leaving no
/// persisted candidate claim.
pub fn admit_imported_evidence_claim(
    vault: &crate::Vault,
    claim: &NormalizedIngestClaim,
    admission: ImportedEvidenceAdmission,
) -> crate::Result<()> {
    if admission.source_id.trim().is_empty() {
        return Err(crate::error::Error::InvalidClaimBody(
            "imported evidence missing source_id",
        ));
    }
    if claim.source_record_id.trim().is_empty() {
        return Err(crate::error::Error::InvalidClaimBody(
            "imported evidence missing source_record_id",
        ));
    }

    let imported_evidence = imported_evidence_value(&admission.source_id, &claim.source_record_id);
    let candidate = ClaimCandidate::new(
        claim.predicate.clone(),
        ClaimSubject::Entity(admission.entity_resolution.subject),
        json_to_msgpack_value(&claim.value),
        1.0,
    )
    .with_evidence(imported_evidence.clone());
    let envelope = WriteEnvelope::new(
        admission.actor,
        ClaimSource::Imported,
        WriteProvenance::new(imported_evidence)?,
        admission.approval,
    );

    vault
        .batch()
        .claim_candidate(
            &admission.claim_id,
            candidate,
            &envelope,
            admission.occurred,
            admission.learned_at,
        )
        .commit()
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

    // The meeting-transcript artifact is one document rather than a line
    // stream, so its failures name the offending path or id instead of a line.
    #[error("ingest source `{source_id}` document has invalid JSON: {message}")]
    InvalidDocument {
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
            note_fallback: None,
        })
    }
}

/// Normalizes the `oneiron.meeting_transcript.v1` producer artifact.
///
/// Normalization stays pre-semantic: corrected turns become records, the
/// producer's structured cleanup stays producer metadata, and no claim is ever
/// emitted. Turn text is already corrected upstream, so this layer validates
/// and maps rather than interpreting.
pub struct MeetingTranscriptSource;

impl IngestSource for MeetingTranscriptSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let document: Value =
            serde_json::from_str(input).map_err(|err| IngestError::InvalidDocument {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                message: err.to_string(),
            })?;
        let document = document
            .as_object()
            .ok_or_else(|| document_field_error("<root>"))?;

        let schema = document_string(document, "schema")?;
        if schema != MEETING_TRANSCRIPT_SCHEMA_V1 {
            return Err(IngestError::UnsupportedSchema {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                expected: MEETING_TRANSCRIPT_SCHEMA_V1,
                found: schema.to_owned(),
            });
        }

        let recording = document_object(document, "recording")?;
        let recording_id = document_string(recording, "recording.recording_id")?;
        if recording_id.trim().is_empty() {
            return Err(document_field_error("recording.recording_id"));
        }
        let duration_ms = document_u64(recording, "recording.duration_ms")?;
        // Capture time anchors every turn into wall-clock; without it turns are
        // still ordered and offset-bearing, so they normalize with no
        // `occurred_at` rather than failing the batch.
        let capture_started_at = optional_document_u64(recording, "recording.capture_started_at")?;

        let word_ids = collect_word_ids(document)?;
        let turns = document_array(document, "turns")?;
        let mut records = Vec::with_capacity(turns.len());
        let mut seen_turn_ids = std::collections::HashSet::with_capacity(turns.len());
        let mut previous_end_ms = 0_u64;

        for (index, turn) in turns.iter().enumerate() {
            let turn = turn
                .as_object()
                .ok_or_else(|| document_field_error(&format!("turns[{index}]")))?;
            let turn_id = document_string(turn, &format!("turns[{index}].turn_id"))?;
            if turn_id.trim().is_empty() {
                return Err(document_field_error(&format!("turns[{index}].turn_id")));
            }
            if !seen_turn_ids.insert(turn_id.to_owned()) {
                return Err(IngestError::DuplicateId {
                    source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                    kind: "turn",
                    id: turn_id.to_owned(),
                });
            }

            let start_ms = document_u64(turn, &format!("turns[{index}].start_ms"))?;
            let end_ms = document_u64(turn, &format!("turns[{index}].end_ms"))?;
            // Turns are time-ordered, non-overlapping, and inside the
            // recording: anything else means the producer's time mapping broke,
            // and mapped `occurred_at` values would silently lie.
            if end_ms < start_ms || start_ms < previous_end_ms || end_ms > duration_ms {
                return Err(IngestError::InvalidTurnTimestamps {
                    source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                    turn_id: turn_id.to_owned(),
                });
            }
            previous_end_ms = end_ms;

            let text = normalize_space(document_string(turn, &format!("turns[{index}].text"))?);
            if text.is_empty() {
                return Err(document_field_error(&format!("turns[{index}].text")));
            }

            for word_ref in document_array(turn, &format!("turns[{index}].source_word_ids"))? {
                let word_ref = word_ref.as_str().ok_or_else(|| {
                    document_field_error(&format!("turns[{index}].source_word_ids"))
                })?;
                if !word_ids.contains(word_ref) {
                    return Err(IngestError::UnknownWordReference {
                        source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                        turn_id: turn_id.to_owned(),
                        word_id: word_ref.to_owned(),
                    });
                }
            }

            records.push(NormalizedIngestRecord {
                source_record_id: turn_id.to_owned(),
                thread_id: Some(recording_id.to_owned()),
                // A resolved identity outranks the anonymous cluster that
                // produced it; with neither, the turn is speaker-less rather
                // than attributed to a guess.
                speaker: optional_document_string(turn, &format!("turns[{index}].speaker_ref"))?
                    .or(optional_document_string(
                        turn,
                        &format!("turns[{index}].speaker_cluster"),
                    )?)
                    .map(str::to_owned),
                occurred_at: capture_started_at.map(|base| base + start_ms / 1000),
                text,
            });
        }

        Ok(NormalizedIngestBatch {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            records,
            claims: Vec::new(),
            note_fallback: note_fallback(document, recording_id, capture_started_at)?,
        })
    }
}

/// Collects word ids, rejecting duplicates so turn references stay unambiguous.
fn collect_word_ids(
    document: &Map<String, Value>,
) -> IngestResult<std::collections::HashSet<String>> {
    let words = document_array(document, "words")?;
    let mut ids = std::collections::HashSet::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let word = word
            .as_object()
            .ok_or_else(|| document_field_error(&format!("words[{index}]")))?;
        let word_id = document_string(word, &format!("words[{index}].word_id"))?;
        if word_id.trim().is_empty() {
            return Err(document_field_error(&format!("words[{index}].word_id")));
        }
        if !ids.insert(word_id.to_owned()) {
            return Err(IngestError::DuplicateId {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                kind: "word",
                id: word_id.to_owned(),
            });
        }
    }
    Ok(ids)
}

fn note_fallback(
    document: &Map<String, Value>,
    recording_id: &str,
    capture_started_at: Option<u64>,
) -> IngestResult<Option<NormalizedIngestNote>> {
    let Some(note) = document.get("note_fallback") else {
        return Ok(None);
    };
    if note.is_null() {
        return Ok(None);
    }
    let note = note
        .as_object()
        .ok_or_else(|| document_field_error("note_fallback"))?;

    let title = normalize_space(document_string(note, "note_fallback.title")?);
    let text = document_string(note, "note_fallback.body")?
        .trim()
        .to_owned();
    if title.is_empty() || text.is_empty() {
        return Err(document_field_error("note_fallback"));
    }

    Ok(Some(NormalizedIngestNote {
        source_record_id: recording_id.to_owned(),
        occurred_at: capture_started_at,
        title,
        text,
    }))
}

fn document_field_error(path: &str) -> IngestError {
    IngestError::InvalidDocumentField {
        source_id: MEETING_TRANSCRIPT_SOURCE_ID,
        path: path.to_owned(),
    }
}

fn document_string<'a>(object: &'a Map<String, Value>, path: &str) -> IngestResult<&'a str> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_str)
        .ok_or_else(|| document_field_error(path))
}

fn optional_document_string<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> IngestResult<Option<&'a str>> {
    match object.get(leaf_key(path)) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| document_field_error(path)),
    }
}

fn document_u64(object: &Map<String, Value>, path: &str) -> IngestResult<u64> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_u64)
        .ok_or_else(|| document_field_error(path))
}

fn optional_document_u64(object: &Map<String, Value>, path: &str) -> IngestResult<Option<u64>> {
    match object.get(leaf_key(path)) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| document_field_error(path)),
    }
}

fn document_object<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> IngestResult<&'a Map<String, Value>> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_object)
        .ok_or_else(|| document_field_error(path))
}

fn document_array<'a>(object: &'a Map<String, Value>, path: &str) -> IngestResult<&'a Vec<Value>> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_array)
        .ok_or_else(|| document_field_error(path))
}

/// The key to look up from a dotted diagnostic path (`turns[0].text` -> `text`).
///
/// Paths exist so an error names where in the document the problem is; lookup
/// only ever needs the last segment, because the caller already holds that
/// object.
fn leaf_key(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

static JSONL_TRANSCRIPT_SOURCE: JsonlTranscriptSource = JsonlTranscriptSource;
static MEETING_TRANSCRIPT_SOURCE: MeetingTranscriptSource = MeetingTranscriptSource;
static INGEST_SOURCE_ENTRIES: [IngestSourceRegistration; 2] = [
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            label: "JSONL transcript",
            format: IngestSourceFormat::JsonlTranscript,
            adapter_skill: None,
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
    ),
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            label: "Meeting transcript",
            format: IngestSourceFormat::MeetingTranscriptV1,
            adapter_skill: Some(IngestAdapterSkillRef {
                skill_id: "builtin.ingest.meeting-transcript",
                version: "1",
            }),
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &MEETING_TRANSCRIPT_SOURCE,
    ),
];

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

fn imported_evidence_value(source_id: &str, source_record_id: &str) -> MsgpackValue {
    MsgpackValue::Map(vec![
        (
            MsgpackValue::from("kind"),
            MsgpackValue::from("imported_evidence"),
        ),
        (
            MsgpackValue::from("source_id"),
            MsgpackValue::from(source_id),
        ),
        (
            MsgpackValue::from("source_record_id"),
            MsgpackValue::from(source_record_id),
        ),
    ])
}

fn json_to_msgpack_value(value: &Value) -> MsgpackValue {
    match value {
        Value::Null => MsgpackValue::Nil,
        Value::Bool(value) => MsgpackValue::Boolean(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                MsgpackValue::from(value)
            } else if let Some(value) = value.as_u64() {
                MsgpackValue::from(value)
            } else if let Some(value) = value.as_f64() {
                MsgpackValue::F64(value)
            } else {
                MsgpackValue::Nil
            }
        }
        Value::String(value) => MsgpackValue::from(value.as_str()),
        Value::Array(values) => {
            MsgpackValue::Array(values.iter().map(json_to_msgpack_value).collect())
        }
        Value::Object(entries) => MsgpackValue::Map(
            entries
                .iter()
                .map(|(key, value)| {
                    (
                        MsgpackValue::from(key.as_str()),
                        json_to_msgpack_value(value),
                    )
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests;
