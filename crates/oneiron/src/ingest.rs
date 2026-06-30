//! Ingest source registry and source-local normalization.
//!
//! Source normalization stops before semantic extraction: sources normalize
//! raw fixture/input records into text-bearing records. Imported evidence can
//! only mint claim writes through an explicit admission helper that requires
//! entity resolution and routes through the normal Gate-backed candidate path.

use rmpv::Value as MsgpackValue;
use serde_json::{Map, Value};

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::types::{
    ClaimCandidate, EntityId, TimeRange, WriteActor, WriteEnvelope, WriteProvenance,
};

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
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::store::Store;
    use crate::types::{
        ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, EdgeActorClass, VaultConfig,
    };

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

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test id")
    }

    fn test_time(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = crate::Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
        (tmp, vault)
    }

    fn normalized_imported_claim() -> NormalizedIngestClaim {
        NormalizedIngestClaim {
            source_record_id: "turn-001".to_owned(),
            predicate: "profile.name".to_owned(),
            value: Value::String("Ada".to_owned()),
        }
    }

    fn proposed_admission(
        claim_id: EntityId,
        subject: EntityId,
        actor: EntityId,
    ) -> ImportedEvidenceAdmission {
        ImportedEvidenceAdmission::proposed(
            JSONL_TRANSCRIPT_SOURCE_ID,
            claim_id,
            ImportedEvidenceEntityResolution::subject(subject),
            WriteActor::new(actor, EdgeActorClass::Human),
            test_time(10),
            10,
        )
    }

    fn put_actor_and_subject(vault: &crate::Vault, actor: &EntityId, subject: &EntityId) {
        vault
            .put_entity(actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")
            .expect("put actor");
        vault
            .put_entity(
                subject,
                ENTITY_TYPE_PERSON,
                test_time(1),
                1,
                b"resolved subject",
            )
            .expect("put subject");
    }

    fn put_malformed_policy_manifest(vault: &crate::Vault, id: &EntityId) {
        let mut payload = Vec::new();
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(b"not a messagepack manifest");

        vault
            .with_write_txn(|wtxn| {
                vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
                let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, id);
                vault.store.type_index.put(wtxn, &type_key, &[])?;
                Ok(())
            })
            .expect("put malformed policy manifest");
    }

    fn evidence_field<'a>(value: &'a MsgpackValue, field: &str) -> Option<&'a MsgpackValue> {
        let MsgpackValue::Map(entries) = value else {
            return None;
        };
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(field)).then_some(value))
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
    fn imported_evidence_admission_defaults_to_proposed_claim() -> crate::Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x11);
        let subject = test_id(0x12);
        let claim_id = test_id(0x13);
        put_actor_and_subject(&vault, &actor, &subject);

        admit_imported_evidence_claim(
            &vault,
            &normalized_imported_claim(),
            proposed_admission(claim_id, subject, actor),
        )?;

        let body = vault
            .get_claim(&claim_id)?
            .expect("imported evidence claim stored for review");
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(body.source, Some(ClaimSource::Imported));
        assert_eq!(body.subject, ClaimSubject::Entity(subject));
        assert_eq!(body.value, MsgpackValue::from("Ada"));
        let evidence = body.evidence.expect("write envelope evidence");
        let candidate_evidence = evidence_field(
            &evidence,
            crate::types::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
        )
        .expect("candidate evidence");
        assert_eq!(
            evidence_field(candidate_evidence, "source_record_id").and_then(MsgpackValue::as_str),
            Some("turn-001")
        );
        Ok(())
    }

    #[test]
    fn imported_evidence_rejects_blank_source_id_before_persistence() -> crate::Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x51);
        let subject = test_id(0x52);
        let claim_id = test_id(0x53);
        put_actor_and_subject(&vault, &actor, &subject);
        let mut admission = proposed_admission(claim_id, subject, actor);
        admission.source_id = " \t\n".to_owned();

        let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
            .expect_err("blank source_id must fail before persistence");

        assert!(
            matches!(
                err,
                Error::InvalidClaimBody("imported evidence missing source_id")
            ),
            "expected InvalidClaimBody for blank source_id, got {err:?}"
        );
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn imported_evidence_rejects_blank_source_record_id_before_persistence() -> crate::Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x61);
        let subject = test_id(0x62);
        let claim_id = test_id(0x63);
        put_actor_and_subject(&vault, &actor, &subject);
        let mut claim = normalized_imported_claim();
        claim.source_record_id = " \t\n".to_owned();

        let err = admit_imported_evidence_claim(
            &vault,
            &claim,
            proposed_admission(claim_id, subject, actor),
        )
        .expect_err("blank source_record_id must fail before persistence");

        assert!(
            matches!(
                err,
                Error::InvalidClaimBody("imported evidence missing source_record_id")
            ),
            "expected InvalidClaimBody for blank source_record_id, got {err:?}"
        );
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn imported_evidence_auto_denial_leaves_no_candidate_claim() -> crate::Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x21);
        let subject = test_id(0x22);
        let claim_id = test_id(0x23);
        put_actor_and_subject(&vault, &actor, &subject);
        let admission =
            proposed_admission(claim_id, subject, actor).with_approval(ClaimApprovalStatus::Auto);

        let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
            .expect_err("imported auto claim must be denied by default");

        assert!(
            matches!(
                err,
                Error::SourceNotTrustedForAuto {
                    claim_source: "imported"
                }
            ),
            "expected imported source-trust denial, got {err:?}"
        );
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn imported_evidence_requires_explicit_resolved_entity_before_persistence() -> crate::Result<()>
    {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x31);
        let missing_subject = test_id(0x32);
        let claim_id = test_id(0x33);
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")?;

        let err = admit_imported_evidence_claim(
            &vault,
            &normalized_imported_claim(),
            proposed_admission(claim_id, missing_subject, actor),
        )
        .expect_err("missing resolved subject entity must abort admission");

        assert!(matches!(err, Error::EntityNotFound), "got {err:?}");
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn imported_evidence_gate_denial_leaves_no_candidate_claim() -> crate::Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x41);
        let subject = test_id(0x42);
        let claim_id = test_id(0x43);
        put_actor_and_subject(&vault, &actor, &subject);
        put_malformed_policy_manifest(&vault, &test_id(0x44));

        let err = admit_imported_evidence_claim(
            &vault,
            &normalized_imported_claim(),
            proposed_admission(claim_id, subject, actor),
        )
        .expect_err("Gate fail-closed denial must abort admission");

        assert!(
            matches!(
                err,
                Error::GateWriteRejected {
                    outcome: "deny",
                    ref reason_codes
                } if reason_codes.as_slice() == ["gate.deny.policy_fail_closed"]
            ),
            "expected Gate deny, got {err:?}"
        );
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
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
