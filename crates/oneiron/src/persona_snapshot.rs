//! OF-325 persona snapshot: compile + export the shareable person-card
//! (PSNAP-1, mode A).
//!
//! `compile_persona_snapshot` assembles a strikeable row list — identity
//! line, key relationships, top-salience claims with provenance refs — with
//! the OF-365 disclosure clamp applied AT COMPILE: Tier A (restricted-band
//! or band-ambiguous claims) never enters the row list, and when the card is
//! FOR someone the audience's scoped-read lane clamps what may enter.
//! Third-party rows default COARSE (name + role); claims about others enter
//! the artifact only via explicit un-strike at preview. Agent takes (OF-330
//! asides) are OFF by default, per-card toggled, and always attributed.
//!
//! `export_persona_snapshot` applies the owner's strike-list (the preview is
//! the consent surface), requires consent content-addressed to the exact
//! compile stamp, renders BOTH artifacts from the one compile
//! (MemoryPack-lite JSON + human markdown card, each carrying compiled-at,
//! the stale_after hint, and the persona compile stamp), and persists an
//! engine-authored export record that projects into the receipt family as a
//! Share receipt carrying `persona_compile_stamp` (RCPT-7 field-set seam).
//!
//! Mode B (grant-backed reference over the share surface) is designed but
//! deliberately NOT built here — a handed copy is a copy; revocation means
//! "don't re-issue".

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead,
    ScopedReadActorKey, claim_sensitivity_band, decode_claim_body,
};
use crate::companion::{CompanionExportClassification, CompanionRecordKind, CompanionScope};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT};
use crate::types::TimeRange;

/// Schema version string carried by every persona snapshot compile stamp.
///
/// The stamp identity (`{schema_version}:{compiled_fingerprint}`) matches the
/// `persona_compile_stamp` value format of the OF-369/RS9 context receipt
/// field-set, so persona-card export receipts and emit receipts read
/// uniformly.
pub const PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION: &str =
    "oneiron.persona_snapshot_compile.v1";

/// Schema marker carried by the MemoryPack-lite JSON render.
pub const MEMORY_PACK_LITE_SCHEMA_VERSION: &str = "oneiron.memory_pack_lite.v1";

/// Current PERSONA_SNAPSHOT_EXPORT record body schema version.
pub const PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for PERSONA_SNAPSHOT_EXPORT bodies.
pub const PERSONA_SNAPSHOT_EXPORT_BODY_KEYS: [&str; 14] = [
    "schemaVersion",
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "compiledFingerprint",
    "takesIncluded",
    "grantedBy",
    "grantedAtSecs",
    "exportedAtSecs",
    "includedRowIds",
    "struckRowIds",
    "artifactFingerprint",
];

/// Minimal projection: enough to answer "what was exported and when?".
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL: &[&str] =
    &["subjectRef", "exportedAtSecs"];

/// Standard projection: the export spine without the row-id lists.
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD: &[&str] = &[
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "grantedBy",
    "exportedAtSecs",
];

/// Full projection: every pinned body key.
pub(crate) const PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL: &[&str] = &PERSONA_SNAPSHOT_EXPORT_BODY_KEYS;

/// Default cap on top-salience subject claim rows in a compile.
pub const DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS: usize = 12;

/// Default per-relationship cap on default-struck third-party claim rows.
pub const DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS: usize = 4;

/// Default stale_after hint (30 days). Consuming agents distrust old copies;
/// this is a freshness HINT on the artifact, not an enforcement TTL.
pub const DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS: u64 = 30 * 86_400;

/// Predicate mined for the identity line's display name.
pub const PERSONA_SNAPSHOT_NAME_PREDICATE: &str = "profile.name";

/// Predicate mined for the identity line's role.
pub const PERSONA_SNAPSHOT_ROLE_PREDICATE: &str = "profile.role";

/// Sensitivity band at or above which a claim is Tier A for disclosure
/// (OF-365): restricted-band claims never enter a compile. A claim whose
/// band cannot be resolved unambiguously also never enters (fail closed).
const TIER_A_MIN_SENSITIVITY_BAND: u8 = 3;

const ROW_ID_PREFIX: &str = "row:";
const ROW_ID_HASH_CHARS: usize = 16;
const MAX_IDENTITY_LINE_BYTES: usize = 2_048;
const FINGERPRINT_HEX_LEN: usize = 64;

/// Identity line persisted on the export record when the owner struck the
/// identity row: the export record is a queryable row, so struck name/role
/// text must not survive in it either.
pub const STRUCK_IDENTITY_LINE_PLACEHOLDER: &str = "(identity struck)";

const KEY_SCHEMA_VERSION: &str = "schemaVersion";
const KEY_SUBJECT_REF: &str = "subjectRef";
const KEY_AUDIENCE_REF: &str = "audienceRef";
const KEY_IDENTITY_LINE: &str = "identityLine";
const KEY_COMPILED_AT_SECS: &str = "compiledAtSecs";
const KEY_STALE_AFTER_SECS: &str = "staleAfterSecs";
const KEY_COMPILED_FINGERPRINT: &str = "compiledFingerprint";
const KEY_TAKES_INCLUDED: &str = "takesIncluded";
const KEY_GRANTED_BY: &str = "grantedBy";
const KEY_GRANTED_AT_SECS: &str = "grantedAtSecs";
const KEY_EXPORTED_AT_SECS: &str = "exportedAtSecs";
const KEY_INCLUDED_ROW_IDS: &str = "includedRowIds";
const KEY_STRUCK_ROW_IDS: &str = "struckRowIds";
const KEY_ARTIFACT_FINGERPRINT: &str = "artifactFingerprint";

/// Row kind on a compiled persona snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaSnapshotRowKind {
    /// The identity line row.
    Identity,
    /// A coarse key-relationship row (name + role).
    Relationship,
    /// A top-salience claim about the card's subject.
    SubjectClaim,
    /// A claim about a third party; default-struck, enters only via
    /// explicit un-strike at preview.
    ThirdPartyClaim,
    /// An actor-attributed agent take (OF-330 aside).
    AgentTake,
}

impl PersonaSnapshotRowKind {
    /// Returns the stable render string for this row kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Relationship => "relationship",
            Self::SubjectClaim => "subject_claim",
            Self::ThirdPartyClaim => "third_party_claim",
            Self::AgentTake => "agent_take",
        }
    }
}

/// One strikeable row of a compiled persona snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotRow {
    /// Content-derived stable row id (strike-list handle).
    pub row_id: String,
    /// Row kind.
    pub kind: PersonaSnapshotRowKind,
    /// Rendered row text (coarse name + role for relationship rows).
    pub text: String,
    /// Entity this row is about.
    pub subject_ref: EntityId,
    /// Salience of the backing claim, when the row is claim-backed.
    pub salience: Option<f32>,
    /// Provenance refs backing this row (`claim:`/`companion:`/`take:`).
    pub provenance_refs: Vec<String>,
    /// Authoring actor ref; always present on agent-take rows.
    pub attribution: Option<String>,
    /// Default strike state at preview (struck rows are absent from the
    /// export unless explicitly un-struck).
    pub struck: bool,
}

/// An actor-attributed agent take supplied to a compile (OF-330 aside).
///
/// The persona snapshot CONSUMES takes; it does not define where they are
/// stored. Callers hand the takes in; the per-card toggle
/// ([`PersonaSnapshotCompileOptions::include_agent_takes`]) gates whether
/// they enter the row list at all.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotAgentTake {
    /// Authoring actor ref; rendered as the attribution, never blank.
    pub actor_ref: String,
    /// The take text.
    pub text: String,
    /// Optional entity the take is about; defaults to the card subject.
    pub about_ref: Option<EntityId>,
}

/// Options for [`crate::Vault::compile_persona_snapshot`].
#[derive(Debug, Clone)]
pub struct PersonaSnapshotCompileOptions {
    /// When the card is FOR someone, their scoped-read actor key; claims
    /// outside the audience's per-contact read scope never enter the
    /// compile (absence is the boundary, not prompt-side withholding).
    pub audience: Option<ScopedReadActorKey>,
    /// Per-card agent-takes toggle; OFF by default. When off, supplied
    /// takes are not consulted at all.
    pub include_agent_takes: bool,
    /// Agent takes offered to this card; only read when
    /// `include_agent_takes` is true.
    pub agent_takes: Vec<PersonaSnapshotAgentTake>,
    /// Cap on top-salience subject claim rows.
    pub max_claim_rows: usize,
    /// Per-relationship cap on default-struck third-party claim rows.
    pub max_third_party_rows: usize,
    /// Relative stale_after freshness hint carried by the artifact.
    pub stale_after_secs: u64,
}

impl Default for PersonaSnapshotCompileOptions {
    fn default() -> Self {
        Self {
            audience: None,
            include_agent_takes: false,
            agent_takes: Vec::new(),
            max_claim_rows: DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS,
            max_third_party_rows: DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS,
            stale_after_secs: DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS,
        }
    }
}

/// Compile stamp minted for every persona snapshot compile.
///
/// The fingerprint is content-addressed over the compiled rows (not the
/// compile time), so an unchanged recompile keeps the same identity and
/// previously granted export consent stays valid — mirroring the
/// `GateConsentBinding` content-addressing law.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotCompileStamp {
    /// Stamp schema version.
    pub schema_version: String,
    /// The card's subject.
    pub subject_ref: EntityId,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// blake3 hex fingerprint over the canonical compiled content.
    pub compiled_fingerprint: String,
}

impl PersonaSnapshotCompileStamp {
    /// Returns the stamp identity in the RCPT-7 `persona_compile_stamp`
    /// value format: `{schema_version}:{fingerprint}`.
    #[must_use]
    pub fn identity(&self) -> String {
        format!("{}:{}", self.schema_version, self.compiled_fingerprint)
    }
}

/// A compiled persona snapshot: the strikeable preview row list plus the
/// compile stamp. This is the consent surface's input; export applies the
/// owner's strike decisions over exactly this compile.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotCompile {
    /// The card's subject.
    pub subject_ref: EntityId,
    /// The compiled identity line.
    pub identity_line: String,
    /// Strikeable rows in render order.
    pub rows: Vec<PersonaSnapshotRow>,
    /// Audience actor ref when the card is FOR someone.
    pub audience_ref: Option<String>,
    /// Whether agent takes were toggled into this card.
    pub takes_included: bool,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint.
    pub stale_after_secs: u64,
    /// The persona compile stamp.
    pub stamp: PersonaSnapshotCompileStamp,
}

/// Strike decisions applied at export over a compile's row list.
///
/// The effective struck set is `(default-struck ∪ strike) − unstrike`;
/// un-striking is the explicit consent step that lets a default-struck
/// third-party row enter the artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonaSnapshotStrikeList {
    /// Row ids struck at preview.
    pub strike: BTreeSet<String>,
    /// Row ids explicitly un-struck at preview.
    pub unstrike: BTreeSet<String>,
}

/// Owner consent presented to an export, content-addressed to the compile
/// stamp it approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotExportConsent {
    /// Consenting actor ref (the owner side of the preview).
    pub granted_by: String,
    /// Stamp identity of the previewed compile this consent approves.
    pub compile_stamp: String,
    /// Consent wall-clock time (Unix seconds).
    pub granted_at_secs: u64,
}

/// The exported persona snapshot artifact: both renders from one compile.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaSnapshotArtifact {
    /// Entity id of the persisted export record.
    pub export_id: EntityId,
    /// The card's subject.
    pub subject_ref: EntityId,
    /// MemoryPack-lite JSON render (agent consumers).
    pub memory_pack_json: String,
    /// Human markdown card render.
    pub markdown: String,
    /// Compile wall-clock time carried by both renders.
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint carried by both renders.
    pub stale_after_secs: u64,
    /// The persona compile stamp.
    pub stamp: PersonaSnapshotCompileStamp,
    /// Row ids included in the artifact, in render order.
    pub included_row_ids: Vec<String>,
    /// Row ids struck out of the artifact.
    pub struck_row_ids: Vec<String>,
}

/// Persisted PERSONA_SNAPSHOT_EXPORT record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotExportRecord {
    /// The card's subject.
    pub subject_ref: EntityId,
    /// Audience actor ref when the card was compiled FOR someone.
    pub audience_ref: Option<String>,
    /// The compiled identity line.
    pub identity_line: String,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint.
    pub stale_after_secs: u64,
    /// blake3 hex fingerprint of the compiled content.
    pub compiled_fingerprint: String,
    /// Whether agent takes were toggled into the card.
    pub takes_included: bool,
    /// Consenting actor ref.
    pub granted_by: String,
    /// Consent wall-clock time (Unix seconds).
    pub granted_at_secs: u64,
    /// Export wall-clock time (Unix seconds).
    pub exported_at_secs: u64,
    /// Row ids included in the artifact.
    pub included_row_ids: Vec<String>,
    /// Row ids struck out of the artifact.
    pub struck_row_ids: Vec<String>,
    /// blake3 hex fingerprint over both renders.
    pub artifact_fingerprint: String,
}

impl PersonaSnapshotExportRecord {
    /// Returns the RCPT-7 `persona_compile_stamp` value for this export.
    #[must_use]
    pub fn compile_stamp_identity(&self) -> String {
        format!(
            "{PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION}:{}",
            self.compiled_fingerprint
        )
    }

    fn validate(&self) -> Result<()> {
        if self.identity_line.is_empty() || self.identity_line.len() > MAX_IDENTITY_LINE_BYTES {
            return Err(invalid_snapshot(
                "identityLine must be non-empty and at most 2048 bytes",
            ));
        }
        validate_fingerprint_hex(&self.compiled_fingerprint)?;
        validate_fingerprint_hex(&self.artifact_fingerprint)?;
        if self.granted_by.trim().is_empty() {
            return Err(invalid_snapshot("grantedBy must be non-empty"));
        }
        if let Some(audience_ref) = self.audience_ref.as_deref()
            && audience_ref.trim().is_empty()
        {
            return Err(invalid_snapshot("audienceRef must be non-empty when set"));
        }
        validate_row_id_list(&self.included_row_ids, "includedRowIds")?;
        validate_row_id_list(&self.struck_row_ids, "struckRowIds")?;
        let struck: BTreeSet<&str> = self.struck_row_ids.iter().map(String::as_str).collect();
        if self
            .included_row_ids
            .iter()
            .any(|row_id| struck.contains(row_id.as_str()))
        {
            return Err(invalid_snapshot(
                "includedRowIds and struckRowIds must be disjoint",
            ));
        }
        Ok(())
    }
}

fn validate_fingerprint_hex(fingerprint: &str) -> Result<()> {
    if fingerprint.len() == FINGERPRINT_HEX_LEN
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid_snapshot(
            "fingerprints must be 64-char lowercase hex",
        ))
    }
}

fn validate_row_id_list(row_ids: &[String], context: &'static str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row_id in row_ids {
        if row_id.is_empty() {
            return Err(invalid_snapshot(match context {
                "includedRowIds" => "includedRowIds entries must be non-empty",
                _ => "struckRowIds entries must be non-empty",
            }));
        }
        if !seen.insert(row_id.as_str()) {
            return Err(invalid_snapshot(match context {
                "includedRowIds" => "includedRowIds entries must be unique",
                _ => "struckRowIds entries must be unique",
            }));
        }
    }
    Ok(())
}

/// Encodes a PERSONA_SNAPSHOT_EXPORT body in canonical MessagePack field order.
pub fn encode_persona_snapshot_export_body(
    record: &PersonaSnapshotExportRecord,
) -> Result<Vec<u8>> {
    record.validate()?;
    let audience_ref = record
        .audience_ref
        .as_deref()
        .map_or(Value::Nil, Value::from);
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SUBJECT_REF),
            Value::from(record.subject_ref.to_hex()),
        ),
        (Value::from(KEY_AUDIENCE_REF), audience_ref),
        (
            Value::from(KEY_IDENTITY_LINE),
            Value::from(record.identity_line.as_str()),
        ),
        (
            Value::from(KEY_COMPILED_AT_SECS),
            Value::from(record.compiled_at_secs),
        ),
        (
            Value::from(KEY_STALE_AFTER_SECS),
            Value::from(record.stale_after_secs),
        ),
        (
            Value::from(KEY_COMPILED_FINGERPRINT),
            Value::from(record.compiled_fingerprint.as_str()),
        ),
        (
            Value::from(KEY_TAKES_INCLUDED),
            Value::from(record.takes_included),
        ),
        (
            Value::from(KEY_GRANTED_BY),
            Value::from(record.granted_by.as_str()),
        ),
        (
            Value::from(KEY_GRANTED_AT_SECS),
            Value::from(record.granted_at_secs),
        ),
        (
            Value::from(KEY_EXPORTED_AT_SECS),
            Value::from(record.exported_at_secs),
        ),
        (
            Value::from(KEY_INCLUDED_ROW_IDS),
            encode_row_ids(&record.included_row_ids),
        ),
        (
            Value::from(KEY_STRUCK_ROW_IDS),
            encode_row_ids(&record.struck_row_ids),
        ),
        (
            Value::from(KEY_ARTIFACT_FINGERPRINT),
            Value::from(record.artifact_fingerprint.as_str()),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("persona snapshot export body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes and validates a PERSONA_SNAPSHOT_EXPORT body.
pub fn decode_persona_snapshot_export_body(bytes: &[u8]) -> Result<PersonaSnapshotExportRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_snapshot("body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_snapshot("trailing bytes after body map"));
    }
    decode_persona_snapshot_export_value(&value)
}

pub(crate) fn validate_persona_snapshot_export_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_persona_snapshot_export_body(bytes).map(|_| ())
}

fn decode_persona_snapshot_export_value(value: &Value) -> Result<PersonaSnapshotExportRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_snapshot("body must be a MessagePack map"));
    };
    validate_keys(entries, &PERSONA_SNAPSHOT_EXPORT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION)
    {
        return Err(invalid_snapshot("unsupported schemaVersion"));
    }

    let record = PersonaSnapshotExportRecord {
        subject_ref: decode_entity_ref(required_value(entries, KEY_SUBJECT_REF)?)?,
        audience_ref: decode_optional_text(required_value(entries, KEY_AUDIENCE_REF)?)?,
        identity_line: decode_text(required_value(entries, KEY_IDENTITY_LINE)?)?,
        compiled_at_secs: decode_u64(required_value(entries, KEY_COMPILED_AT_SECS)?)?,
        stale_after_secs: decode_u64(required_value(entries, KEY_STALE_AFTER_SECS)?)?,
        compiled_fingerprint: decode_text(required_value(entries, KEY_COMPILED_FINGERPRINT)?)?,
        takes_included: required_value(entries, KEY_TAKES_INCLUDED)?
            .as_bool()
            .ok_or_else(|| invalid_snapshot("takesIncluded must be a boolean"))?,
        granted_by: decode_text(required_value(entries, KEY_GRANTED_BY)?)?,
        granted_at_secs: decode_u64(required_value(entries, KEY_GRANTED_AT_SECS)?)?,
        exported_at_secs: decode_u64(required_value(entries, KEY_EXPORTED_AT_SECS)?)?,
        included_row_ids: decode_row_ids(required_value(entries, KEY_INCLUDED_ROW_IDS)?)?,
        struck_row_ids: decode_row_ids(required_value(entries, KEY_STRUCK_ROW_IDS)?)?,
        artifact_fingerprint: decode_text(required_value(entries, KEY_ARTIFACT_FINGERPRINT)?)?,
    };

    record.validate()?;
    Ok(record)
}

fn encode_row_ids(row_ids: &[String]) -> Value {
    Value::Array(
        row_ids
            .iter()
            .map(|row_id| Value::from(row_id.as_str()))
            .collect::<Vec<_>>(),
    )
}

fn decode_row_ids(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_snapshot("row id lists must be arrays"));
    };
    values.iter().map(decode_text).collect()
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid_snapshot("entity refs must be hex strings"))?;
    EntityId::from_hex(hex).map_err(|_| invalid_snapshot("entity refs must be valid entity ids"))
}

fn decode_text(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_snapshot("field must be a UTF-8 string"))
}

fn decode_optional_text(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_text(value).map(Some)
}

fn decode_u64(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid_snapshot("field must be an unsigned integer"))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| invalid_snapshot("body keys must be strings"))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_snapshot(
                "body key is not in the pinned PERSONA_SNAPSHOT_EXPORT_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_snapshot("duplicate body key"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_snapshot("missing required export record field"))
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_snapshot("missing required export record field"))
}

fn invalid_snapshot(reason: &'static str) -> Error {
    Error::InvalidPersonaSnapshot(reason)
}

fn hash_hex(bytes: &[u8]) -> String {
    bytes_to_hex_lower(blake3::hash(bytes).as_bytes())
}

/// Returns true when the OF-365 disclosure clamp bars this claim from ever
/// entering a persona snapshot compile: restricted-band (Tier A) claims and
/// claims whose sensitivity band is ambiguous (fail closed).
pub(crate) fn persona_snapshot_tier_a_clamped(body: &ClaimBody) -> bool {
    match claim_sensitivity_band(body) {
        None => true,
        Some(band) => band >= TIER_A_MIN_SENSITIVITY_BAND,
    }
}

fn admissible_claim(body: &ClaimBody) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active
        && matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
        && !body.stale
}

fn claim_value_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn relationship_role_label(value: &Value) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        if key.as_str() == Some("role") {
            value.as_str().map(str::to_owned)
        } else {
            None
        }
    })
}

fn row_id(
    kind: PersonaSnapshotRowKind,
    subject_ref: &EntityId,
    text: &str,
    attribution: Option<&str>,
    provenance_refs: &[String],
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(kind.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(subject_ref.to_hex().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(attribution.unwrap_or_default().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(provenance_refs.join(",").as_bytes());
    let digest = hash_hex(&bytes);
    format!("{ROW_ID_PREFIX}{}", &digest[..ROW_ID_HASH_CHARS])
}

fn make_row(
    kind: PersonaSnapshotRowKind,
    subject_ref: EntityId,
    text: String,
    salience: Option<f32>,
    provenance_refs: Vec<String>,
    attribution: Option<String>,
    struck: bool,
) -> PersonaSnapshotRow {
    let row_id = row_id(
        kind,
        &subject_ref,
        &text,
        attribution.as_deref(),
        &provenance_refs,
    );
    PersonaSnapshotRow {
        row_id,
        kind,
        text,
        subject_ref,
        salience,
        provenance_refs,
        attribution,
        struck,
    }
}

fn compile_fingerprint(
    subject_ref: &EntityId,
    identity_line: &str,
    audience_ref: Option<&str>,
    takes_included: bool,
    stale_after_secs: u64,
    rows: &[PersonaSnapshotRow],
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(subject_ref.to_hex().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(identity_line.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(audience_ref.unwrap_or_default().as_bytes());
    bytes.push(0);
    bytes.push(u8::from(takes_included));
    bytes.extend_from_slice(&stale_after_secs.to_be_bytes());
    for row in rows {
        bytes.push(b'\n');
        bytes.extend_from_slice(row.row_id.as_bytes());
        bytes.push(0);
        bytes.push(u8::from(row.struck));
        // Salience is rendered on the MemoryPack row, so it is consent-bound
        // content: a salience-only edit must invalidate the stamp identity
        // even though the row id (the strike handle) stays stable.
        match row.salience {
            Some(salience) => {
                bytes.push(1);
                bytes.extend_from_slice(&salience.to_bits().to_be_bytes());
            }
            None => bytes.push(0),
        }
    }
    hash_hex(&bytes)
}

/// Verifies that a compile presented for export still hashes to its own
/// stamp: every row id must re-derive from the row's content, agent-take
/// rows must carry attribution, and the whole compile must re-fingerprint
/// to `stamp.compiled_fingerprint`. `PersonaSnapshotCompile` fields are
/// public, so consent binding is only real if export re-computes the
/// content address instead of trusting the caller's stamp string.
fn verify_compile_against_stamp(compile: &PersonaSnapshotCompile) -> Result<()> {
    for row in &compile.rows {
        if row.kind == PersonaSnapshotRowKind::AgentTake
            && row
                .attribution
                .as_deref()
                .is_none_or(|attribution| attribution.trim().is_empty())
        {
            return Err(invalid_snapshot("agent take rows must carry attribution"));
        }
        let expected = row_id(
            row.kind,
            &row.subject_ref,
            &row.text,
            row.attribution.as_deref(),
            &row.provenance_refs,
        );
        if expected != row.row_id {
            return Err(invalid_snapshot(
                "compile row does not match its content-derived row id",
            ));
        }
    }
    if compile.stamp.schema_version != PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION
        || compile.stamp.subject_ref != compile.subject_ref
    {
        return Err(invalid_snapshot(
            "compile stamp header does not match the compile",
        ));
    }
    let expected = compile_fingerprint(
        &compile.subject_ref,
        &compile.identity_line,
        compile.audience_ref.as_deref(),
        compile.takes_included,
        compile.stale_after_secs,
        &compile.rows,
    );
    if expected != compile.stamp.compiled_fingerprint {
        return Err(invalid_snapshot(
            "compile content does not match its stamp fingerprint",
        ));
    }
    Ok(())
}

struct CandidateClaim {
    id: EntityId,
    body: ClaimBody,
}

impl CandidateClaim {
    fn provenance_ref(&self) -> String {
        format!("claim:{}", self.id.to_hex())
    }
}

fn top_claim_text<'a>(
    candidates: &'a [CandidateClaim],
    predicate: &str,
) -> Option<(&'a CandidateClaim, String)> {
    candidates
        .iter()
        .find(|candidate| candidate.body.predicate == predicate)
        .and_then(|candidate| {
            let text = candidate.body.value.as_str()?.trim();
            (!text.is_empty()).then(|| (candidate, text.to_owned()))
        })
}

fn person_fallback_label(person_ref: &EntityId) -> String {
    format!("person {}", &person_ref.to_hex()[..8])
}

/// Collapses newline runs to single spaces so vault text can never open a
/// new markdown block (heading, list item, code fence) inside the card.
fn markdown_safe_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_break = false;
    for ch in text.chars() {
        if ch == '\n' || ch == '\r' {
            in_break = true;
            continue;
        }
        if in_break {
            out.push(' ');
            in_break = false;
        }
        out.push(ch);
    }
    out
}

impl crate::Vault {
    /// Compiles the OF-325 persona snapshot preview for `subject_ref`: the
    /// strikeable row list plus the persona compile stamp.
    ///
    /// The OF-365 disclosure clamp applies here, at compile: Tier A never
    /// enters the row list, and when `options.audience` names who the card
    /// is FOR, claims outside that actor's scoped-read lane never enter
    /// either. Third-party relationship rows enter COARSE (name + role);
    /// third-party claim rows enter default-struck.
    pub fn compile_persona_snapshot(
        &self,
        subject_ref: &EntityId,
        options: &PersonaSnapshotCompileOptions,
    ) -> Result<PersonaSnapshotCompile> {
        let Some(raw) = self.get_raw(subject_ref)? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_PERSON {
            return Err(invalid_snapshot("subject must be a PERSON entity"));
        }
        // A user_delete soft erase keeps a bodiless header shell; a deleted
        // person is absent for compilation, never a fallback card.
        if raw.len() <= ENTITY_METADATA_HEADER_LEN {
            return Err(Error::EntityNotFound);
        }

        let audience_read = options
            .audience
            .as_ref()
            .map(|key| self.scoped_read(key.clone()));
        let audience_ref = options
            .audience
            .as_ref()
            .map(|key| key.actor_ref().to_owned());

        let subject_claims =
            self.persona_snapshot_candidate_claims(subject_ref, audience_read.as_ref())?;

        let mut identity_provenance = Vec::new();
        let mut identity_claim_ids = BTreeSet::new();
        let name = top_claim_text(&subject_claims, PERSONA_SNAPSHOT_NAME_PREDICATE);
        let role = top_claim_text(&subject_claims, PERSONA_SNAPSHOT_ROLE_PREDICATE);
        if let Some((candidate, _)) = &name {
            identity_provenance.push(candidate.provenance_ref());
            identity_claim_ids.insert(candidate.id);
        }
        if let Some((candidate, _)) = &role {
            identity_provenance.push(candidate.provenance_ref());
            identity_claim_ids.insert(candidate.id);
        }
        let identity_line = match (&name, &role) {
            (Some((_, name)), Some((_, role))) => format!("{name} — {role}"),
            (Some((_, name)), None) => name.clone(),
            (None, _) => person_fallback_label(subject_ref),
        };

        let mut rows = Vec::new();
        let mut seen_row_ids = BTreeSet::new();
        let mut push_row = |rows: &mut Vec<PersonaSnapshotRow>, row: PersonaSnapshotRow| {
            if seen_row_ids.insert(row.row_id.clone()) {
                rows.push(row);
            }
        };

        push_row(
            &mut rows,
            make_row(
                PersonaSnapshotRowKind::Identity,
                *subject_ref,
                identity_line.clone(),
                None,
                identity_provenance,
                None,
                false,
            ),
        );

        // Key relationships from the companion register, honoring the
        // portable-export law (Portable classification, never SharedVault
        // scope — matching `export.rs::companion_record_exportable`).
        let register = self.companion_register()?;
        let mut related: BTreeMap<EntityId, (Option<String>, String)> = BTreeMap::new();
        for (key, record) in register.iter() {
            if record.kind() != CompanionRecordKind::Relationship
                || record.export_classification != CompanionExportClassification::Portable
                || matches!(record.scope, CompanionScope::SharedVault { .. })
            {
                continue;
            }
            let crate::companion::CompanionSubject::Relationship {
                source_ref,
                target_ref,
            } = &record.subject
            else {
                continue;
            };
            let (source_ref, target_ref) = (*source_ref, *target_ref);
            let other = if source_ref == *subject_ref {
                target_ref
            } else if target_ref == *subject_ref {
                source_ref
            } else {
                continue;
            };
            if other == *subject_ref {
                continue;
            }
            let record_ref = self.companion_record_id_for_key(key)?.map_or_else(
                || format!("companion:{}:{}", source_ref.to_hex(), target_ref.to_hex()),
                |id| format!("companion:{}", id.to_hex()),
            );
            related
                .entry(other)
                .or_insert((relationship_role_label(&record.value), record_ref));
        }

        let mut third_party_rows = Vec::new();
        for (other, (record_role, record_ref)) in &related {
            let other_claims =
                self.persona_snapshot_candidate_claims(other, audience_read.as_ref())?;
            let other_name = top_claim_text(&other_claims, PERSONA_SNAPSHOT_NAME_PREDICATE)
                .map_or_else(|| person_fallback_label(other), |(_, name)| name);
            let role = record_role.clone().or_else(|| {
                top_claim_text(&other_claims, PERSONA_SNAPSHOT_ROLE_PREDICATE).map(|(_, role)| role)
            });
            let text = role.map_or_else(
                || format!("{other_name} — relationship"),
                |role| format!("{other_name} — {role}"),
            );
            push_row(
                &mut rows,
                make_row(
                    PersonaSnapshotRowKind::Relationship,
                    *other,
                    text,
                    None,
                    vec![record_ref.clone()],
                    None,
                    false,
                ),
            );

            // Claims about others never enter the default card: they are
            // compiled as default-struck rows so explicit un-strike at
            // preview is the only door in.
            for candidate in other_claims
                .iter()
                .filter(|candidate| {
                    candidate.body.predicate != PERSONA_SNAPSHOT_NAME_PREDICATE
                        && candidate.body.predicate != PERSONA_SNAPSHOT_ROLE_PREDICATE
                })
                .take(options.max_third_party_rows)
            {
                third_party_rows.push(make_row(
                    PersonaSnapshotRowKind::ThirdPartyClaim,
                    *other,
                    format!(
                        "{}: {}",
                        candidate.body.predicate,
                        claim_value_text(&candidate.body.value)
                    ),
                    candidate.body.salience,
                    vec![candidate.provenance_ref()],
                    None,
                    true,
                ));
            }
        }

        for candidate in subject_claims
            .iter()
            .filter(|candidate| !identity_claim_ids.contains(&candidate.id))
            .take(options.max_claim_rows)
        {
            push_row(
                &mut rows,
                make_row(
                    PersonaSnapshotRowKind::SubjectClaim,
                    *subject_ref,
                    format!(
                        "{}: {}",
                        candidate.body.predicate,
                        claim_value_text(&candidate.body.value)
                    ),
                    candidate.body.salience,
                    vec![candidate.provenance_ref()],
                    None,
                    false,
                ),
            );
        }

        for row in third_party_rows {
            push_row(&mut rows, row);
        }

        let takes_included = options.include_agent_takes && !options.agent_takes.is_empty();
        if takes_included {
            for take in &options.agent_takes {
                let actor_ref = take.actor_ref.trim();
                if actor_ref.is_empty() {
                    return Err(invalid_snapshot("agent take actor_ref must be non-empty"));
                }
                if take.text.trim().is_empty() {
                    return Err(invalid_snapshot("agent take text must be non-empty"));
                }
                let about = take.about_ref.unwrap_or(*subject_ref);
                push_row(
                    &mut rows,
                    make_row(
                        PersonaSnapshotRowKind::AgentTake,
                        about,
                        take.text.trim().to_owned(),
                        None,
                        vec![format!("take:{actor_ref}")],
                        Some(actor_ref.to_owned()),
                        false,
                    ),
                );
            }
        }

        let compiled_fingerprint = compile_fingerprint(
            subject_ref,
            &identity_line,
            audience_ref.as_deref(),
            takes_included,
            options.stale_after_secs,
            &rows,
        );
        let stamp = PersonaSnapshotCompileStamp {
            schema_version: PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION.to_owned(),
            subject_ref: *subject_ref,
            compiled_at_secs: crate::unix_seconds_now(),
            compiled_fingerprint,
        };

        Ok(PersonaSnapshotCompile {
            subject_ref: *subject_ref,
            identity_line,
            rows,
            audience_ref,
            takes_included,
            compiled_at_secs: stamp.compiled_at_secs,
            stale_after_secs: options.stale_after_secs,
            stamp,
        })
    }

    /// Exports the OF-325 persona snapshot artifact (mode A): applies the
    /// preview strike-list over `compile`, renders BOTH artifacts from the
    /// one compile, persists the export record, and thereby emits the Share
    /// receipt carrying `persona_compile_stamp`.
    ///
    /// Consent is content-addressed: `consent.compile_stamp` must equal the
    /// compile's stamp identity, so consent granted over one preview can
    /// never issue a different compile.
    pub fn export_persona_snapshot(
        &self,
        compile: &PersonaSnapshotCompile,
        strikes: &PersonaSnapshotStrikeList,
        consent: &PersonaSnapshotExportConsent,
    ) -> Result<PersonaSnapshotArtifact> {
        if consent.granted_by.trim().is_empty() {
            return Err(invalid_snapshot(
                "export consent granted_by must be non-empty",
            ));
        }
        verify_compile_against_stamp(compile)?;
        let compile_stamp = compile.stamp.identity();
        if consent.compile_stamp != compile_stamp {
            return Err(Error::PersonaSnapshotConsentStale {
                consent_stamp: consent.compile_stamp.clone(),
                compile_stamp,
            });
        }

        let known_row_ids: BTreeSet<&str> =
            compile.rows.iter().map(|row| row.row_id.as_str()).collect();
        for row_id in strikes.strike.iter().chain(strikes.unstrike.iter()) {
            if !known_row_ids.contains(row_id.as_str()) {
                return Err(invalid_snapshot("strike list references unknown row id"));
            }
        }
        if strikes
            .strike
            .iter()
            .any(|row_id| strikes.unstrike.contains(row_id))
        {
            return Err(invalid_snapshot("strike and unstrike must not overlap"));
        }

        let mut included = Vec::new();
        let mut struck_row_ids = Vec::new();
        for row in &compile.rows {
            let struck = (row.struck || strikes.strike.contains(&row.row_id))
                && !strikes.unstrike.contains(&row.row_id);
            if struck {
                struck_row_ids.push(row.row_id.clone());
            } else {
                included.push(row);
            }
        }
        let included_row_ids: Vec<String> = included.iter().map(|row| row.row_id.clone()).collect();

        let identity_included = included
            .iter()
            .any(|row| row.kind == PersonaSnapshotRowKind::Identity);
        let memory_pack_json = render_memory_pack_lite(compile, &included, identity_included);
        let markdown = render_markdown_card(compile, &included, identity_included);

        let mut artifact_bytes = Vec::new();
        artifact_bytes.extend_from_slice(memory_pack_json.as_bytes());
        artifact_bytes.push(0);
        artifact_bytes.extend_from_slice(markdown.as_bytes());
        let artifact_fingerprint = hash_hex(&artifact_bytes);

        // A struck identity row means the name/role never leaves the vault:
        // the export record is itself a queryable row, so it must not retain
        // the struck text either.
        let recorded_identity_line = if identity_included {
            compile.identity_line.clone()
        } else {
            STRUCK_IDENTITY_LINE_PLACEHOLDER.to_owned()
        };
        let record = PersonaSnapshotExportRecord {
            subject_ref: compile.subject_ref,
            audience_ref: compile.audience_ref.clone(),
            identity_line: recorded_identity_line,
            compiled_at_secs: compile.compiled_at_secs,
            stale_after_secs: compile.stale_after_secs,
            compiled_fingerprint: compile.stamp.compiled_fingerprint.clone(),
            takes_included: compile.takes_included,
            granted_by: consent.granted_by.trim().to_owned(),
            granted_at_secs: consent.granted_at_secs,
            exported_at_secs: crate::unix_seconds_now(),
            included_row_ids: included_row_ids.clone(),
            struck_row_ids: struck_row_ids.clone(),
            artifact_fingerprint,
        };
        let export_id = EntityId::now();
        self.put_persona_snapshot_export(&export_id, &record)?;

        Ok(PersonaSnapshotArtifact {
            export_id,
            subject_ref: compile.subject_ref,
            memory_pack_json,
            markdown,
            compiled_at_secs: compile.compiled_at_secs,
            stale_after_secs: compile.stale_after_secs,
            stamp: compile.stamp.clone(),
            included_row_ids,
            struck_row_ids,
        })
    }

    /// Stores an engine-authored PERSONA_SNAPSHOT_EXPORT record.
    ///
    /// Generic public puts of the kind remain rejected as a maintenance
    /// kind; this helper validates the pinned body schema before using the
    /// internal maintenance write path.
    pub fn put_persona_snapshot_export(
        &self,
        id: &EntityId,
        record: &PersonaSnapshotExportRecord,
    ) -> Result<()> {
        let data = encode_persona_snapshot_export_body(record)?;
        let learned_at = record.exported_at_secs;
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted.load(Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads and decodes a PERSONA_SNAPSHOT_EXPORT record.
    pub fn get_persona_snapshot_export(
        &self,
        id: &EntityId,
    ) -> Result<Option<PersonaSnapshotExportRecord>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_persona_snapshot_export_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn persona_snapshot_candidate_claims(
        &self,
        person_ref: &EntityId,
        audience: Option<&ScopedRead<'_>>,
    ) -> Result<Vec<CandidateClaim>> {
        let mut candidates = Vec::new();
        for claim_id in self.claims_for_subject(person_ref)? {
            let Some(raw) = self.get_raw(&claim_id)? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let body_bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
            if body_bytes.is_empty() {
                // A user_delete soft erase keeps a bodiless claim shell in
                // the claim_of index; deleted claims are suppressed, never
                // an error that blocks the whole compile.
                continue;
            }
            let body = decode_claim_body(body_bytes, true)?;
            if body.subject != ClaimSubject::Entity(*person_ref) || !admissible_claim(&body) {
                continue;
            }
            if persona_snapshot_tier_a_clamped(&body) {
                continue;
            }
            if let Some(audience) = audience
                && !audience.is_entity_readable(&claim_id)?
            {
                continue;
            }
            candidates.push(CandidateClaim { id: claim_id, body });
        }
        candidates.sort_by(|a, b| {
            let a_salience = a.body.salience.unwrap_or(-1.0);
            let b_salience = b.body.salience.unwrap_or(-1.0);
            b_salience
                .total_cmp(&a_salience)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(candidates)
    }
}

fn render_memory_pack_lite(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let rows: Vec<serde_json::Value> = included
        .iter()
        .map(|row| {
            // Relationship rows stay COARSE in the exported artifact: name +
            // role text only, no third-party entity ids or vault-internal
            // provenance refs (those exceed the coarse default; claim rows
            // about others only appear at all via explicit un-strike).
            if row.kind == PersonaSnapshotRowKind::Relationship {
                return serde_json::json!({
                    "row_id": row.row_id,
                    "kind": row.kind.as_str(),
                    "text": row.text,
                });
            }
            let mut entry = serde_json::json!({
                "row_id": row.row_id,
                "kind": row.kind.as_str(),
                "text": row.text,
                "subject_ref": row.subject_ref.to_hex(),
                "provenance_refs": row.provenance_refs,
            });
            if let Some(salience) = row.salience {
                entry["salience"] = serde_json::json!(salience);
            }
            if let Some(attribution) = &row.attribution {
                entry["attribution"] = serde_json::json!(attribution);
            }
            entry
        })
        .collect();

    let pack = serde_json::json!({
        "schema": MEMORY_PACK_LITE_SCHEMA_VERSION,
        "kind": "persona_snapshot",
        "subject_ref": compile.subject_ref.to_hex(),
        "identity_line": identity_included
            .then(|| compile.identity_line.clone()),
        "audience_ref": compile.audience_ref,
        "takes_included": compile.takes_included,
        "compiled_at_secs": compile.compiled_at_secs,
        "stale_after_secs": compile.stale_after_secs,
        "persona_compile_stamp": compile.stamp.identity(),
        "rows": rows,
    });
    pack.to_string()
}

fn render_markdown_card(
    compile: &PersonaSnapshotCompile,
    included: &[&PersonaSnapshotRow],
    identity_included: bool,
) -> String {
    let mut out = String::new();
    if identity_included {
        out.push_str(&format!(
            "# {}\n",
            markdown_safe_line(&compile.identity_line)
        ));
    } else {
        out.push_str("# Persona snapshot\n");
    }
    out.push('\n');
    out.push_str(&format!("- subject: {}\n", compile.subject_ref.to_hex()));
    if let Some(audience_ref) = &compile.audience_ref {
        out.push_str(&format!("- for: {audience_ref}\n"));
    }
    out.push_str(&format!(
        "- compiled_at_secs: {}\n",
        compile.compiled_at_secs
    ));
    out.push_str(&format!(
        "- stale_after_secs: {}\n",
        compile.stale_after_secs
    ));
    out.push_str(&format!(
        "- persona_compile_stamp: {}\n",
        compile.stamp.identity()
    ));

    let mut push_section = |title: &str, kind: PersonaSnapshotRowKind| {
        let rows: Vec<&&PersonaSnapshotRow> =
            included.iter().filter(|row| row.kind == kind).collect();
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("\n## {title}\n\n"));
        for row in rows {
            // Relationship rows stay COARSE in the exported artifact:
            // name + role text only, no vault-internal provenance refs.
            let provenance = if row.provenance_refs.is_empty()
                || row.kind == PersonaSnapshotRowKind::Relationship
            {
                String::new()
            } else {
                format!(" `[{}]`", row.provenance_refs.join(", "))
            };
            let text = markdown_safe_line(&row.text);
            match &row.attribution {
                Some(attribution) => {
                    out.push_str(&format!(
                        "- {} (take): {text}{provenance}\n",
                        markdown_safe_line(attribution)
                    ));
                }
                None => out.push_str(&format!("- {text}{provenance}\n")),
            }
        }
    };

    push_section("Key relationships", PersonaSnapshotRowKind::Relationship);
    push_section("Claims", PersonaSnapshotRowKind::SubjectClaim);
    push_section(
        "Third-party details",
        PersonaSnapshotRowKind::ThirdPartyClaim,
    );
    push_section("Agent takes", PersonaSnapshotRowKind::AgentTake);
    out
}

#[cfg(test)]
mod tests;
