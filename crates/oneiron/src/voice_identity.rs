//! VOX-02 voice identity substrate: consent log, enrollment, local matching.
//!
//! One embedding space at a time, consent-gated enrollment, deterministic
//! enrolled-principal matching, residual-only stranger clustering, and
//! non-biometric invite/elimination naming. Every biometric row is a private
//! home-node `vault_meta` sidecar (the `session_lifecycle` / `disclosure`
//! enforcement-record pattern): no entity type byte is allocated, so a
//! centroid can never reach retrieval, context assembly, or sync. Withdrawal
//! is therefore a plain atomic deletion of those private rows.
//!
//! Split of authority:
//!
//! * **Consent is the capability door.** Enrollment reads a stored
//!   [`VoiceConsentEventV1`] that is `Granted`, covers the requested purpose,
//!   and precedes the request. A later withdrawal for the same purpose
//!   permanently closes that door; a granted record alone is not enough.
//! * **Matching is local and total.** Segment vectors are compared only with
//!   active centroids in the SAME embedding space. A cross-space comparison is
//!   an error, never a low score, so a model/revision/preprocessing change
//!   forces re-enrollment instead of silently reusing an old centroid.
//! * **Naming never lowers the bar.** Invite elimination runs after residual
//!   clustering, only on an unambiguous one-to-one remainder, and changes the
//!   display/reference evidence — never a biometric score.
//!
//! The resolved roster is vector-free by construction and is the only thing
//! the ILD-3 interlocutor seam consumes. `owner_print_matched` stays display
//! corroboration: an authenticated session remains the sole path to an
//! `Owner`-class interlocutor entry.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Cursor;

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_RELATIONSHIP};
use crate::store::Store;

/// Ticket-owned default known-speaker acceptance threshold (cosine).
pub const VOICE_MATCH_THRESHOLD_DEFAULT: f32 = 0.65;
/// Lowest known-speaker threshold this engine accepts.
pub const VOICE_MATCH_THRESHOLD_MIN: f32 = 0.55;
/// Highest known-speaker threshold this engine accepts.
pub const VOICE_MATCH_THRESHOLD_MAX: f32 = 0.75;

/// Schema version stamped into every voice-identity sidecar body.
const VOICE_IDENTITY_SCHEMA_VERSION: u64 = 1;

/// Distinct language tags a centroid needs before it is `Calibrated`.
const VOICE_CALIBRATION_MIN_LANGUAGES: usize = 2;

/// Upper bound on segments in one match request.
///
/// Residual clustering is quadratic in the residual count; this bound keeps a
/// single request from turning into an unbounded local job. It is a
/// ticket-owned dial, not a canon-frozen constant.
const VOICE_MAX_MATCH_SEGMENTS: usize = 1024;

/// `vault_meta` key prefix for voice print rows and the active-space pointer.
const VOICE_PRINT_KEY_PREFIX: &[u8] = b"voice_identity.print.v1:";
/// `vault_meta` key prefix for stored enrollment sample/vector rows.
const VOICE_SAMPLE_KEY_PREFIX: &[u8] = b"voice_identity.sample.v1:";
/// `vault_meta` key prefix for consent/withdrawal event rows.
const VOICE_CONSENT_KEY_PREFIX: &[u8] = b"voice_identity.consent.v1:";
/// `vault_meta` key prefix for resolved session roster rows.
const VOICE_ROSTER_KEY_PREFIX: &[u8] = b"voice_identity.roster.v1:";

/// Purpose a voice print may be used for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoicePrintPurpose {
    /// Attributing speakers inside recorded meeting material.
    MeetingAttribution,
    /// Attributing the live conversation partner in session.
    LiveInterlocutor,
}

impl VoicePrintPurpose {
    /// Returns the pinned on-disk string for this purpose.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MeetingAttribution => "meeting_attribution",
            Self::LiveInterlocutor => "live_interlocutor",
        }
    }

    /// Parses a pinned on-disk purpose string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "meeting_attribution" => Some(Self::MeetingAttribution),
            "live_interlocutor" => Some(Self::LiveInterlocutor),
            _ => None,
        }
    }
}

/// Whether a consent record grants or withdraws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceConsentState {
    Granted,
    Withdrawn,
}

impl VoiceConsentState {
    /// Returns the pinned on-disk string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Parses a pinned on-disk state string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "granted" => Some(Self::Granted),
            "withdrawn" => Some(Self::Withdrawn),
            _ => None,
        }
    }
}

/// Where one enrollment sample came from.
///
/// The two shapes are the two admissible provenances: a principal's own
/// authenticated solo session, or a specifically consented diarized segment of
/// a named recording. Multi-speaker meeting audio can only ever arrive through
/// the second shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoiceEnrollmentOrigin {
    AuthenticatedSoloSession {
        session_ref: String,
        speaker_count: u32,
    },
    ConsentedDiarizedSegment {
        recording_ref: String,
        segment_id: String,
    },
}

/// Speaker-embedding model family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceEmbeddingFamily {
    /// The shipped v1 active family.
    EcapaTdnn,
    /// Supported config shape for a future re-enrollment migration. It is
    /// never a second active space alongside `EcapaTdnn`.
    CamPlusPlus,
}

impl VoiceEmbeddingFamily {
    /// Returns the pinned on-disk string for this family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcapaTdnn => "ecapa_tdnn",
            Self::CamPlusPlus => "cam_plus_plus",
        }
    }

    /// Parses a pinned on-disk family string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ecapa_tdnn" => Some(Self::EcapaTdnn),
            "cam_plus_plus" => Some(Self::CamPlusPlus),
            _ => None,
        }
    }
}

/// How well spread a stored centroid's enrollment material is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoicePrintCalibration {
    /// Fewer than two distinct language tags: usable, never called calibrated.
    Collecting,
    /// Mixed-language enrollment material.
    Calibrated,
}

impl VoicePrintCalibration {
    /// Returns the pinned on-disk string for this calibration state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Calibrated => "calibrated",
        }
    }

    /// Parses a pinned on-disk calibration string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "collecting" => Some(Self::Collecting),
            "calibrated" => Some(Self::Calibrated),
            _ => None,
        }
    }
}

/// How a consent decision was captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoiceConsentBasis {
    ConversationalNotice {
        notice: String,
    },
    /// A spoken grant inside a named recording at a named time span. A first
    /// class basis, not a placeholder.
    VerbalOnRecording {
        recording_ref: String,
        start_ms: u64,
        end_ms: u64,
        words: String,
    },
    SettingsToggle {
        surface_ref: String,
    },
}

impl VoiceConsentBasis {
    /// Validates the shape-specific requirements of this basis.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ConversationalNotice { notice } => {
                require_non_empty(notice, "voice consent notice")
            }
            Self::VerbalOnRecording {
                recording_ref,
                start_ms,
                end_ms,
                words,
            } => {
                require_non_empty(recording_ref, "voice consent recording ref")?;
                require_non_empty(words, "voice consent words")?;
                if start_ms >= end_ms {
                    return Err(invalid_voice(
                        "verbal-on-recording consent needs start_ms < end_ms",
                    ));
                }
                Ok(())
            }
            Self::SettingsToggle { surface_ref } => {
                require_non_empty(surface_ref, "voice consent surface ref")
            }
        }
    }

    /// Returns the recording this basis names, when it names one.
    #[must_use]
    pub fn recording_ref(&self) -> Option<&str> {
        match self {
            Self::VerbalOnRecording { recording_ref, .. } => Some(recording_ref.as_str()),
            Self::ConversationalNotice { .. } | Self::SettingsToggle { .. } => None,
        }
    }
}

/// One logged consent or withdrawal decision.
///
/// It records who, when, what purposes, how consent was captured, and the
/// evidence refs. It grants no owner authority, no outbound permission, and no
/// disclosure widening, and it never carries a vector or audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceConsentEventV1 {
    pub event_id: String,
    pub subject_ref: EntityId,
    pub recorded_by_ref: EntityId,
    pub occurred_at: u64,
    pub purposes: Vec<VoicePrintPurpose>,
    pub basis: VoiceConsentBasis,
    pub state: VoiceConsentState,
}

impl VoiceConsentEventV1 {
    /// Validates the record before it is stored or trusted.
    pub fn validate(&self) -> Result<()> {
        require_non_empty(&self.event_id, "voice consent event id")?;
        if self.purposes.is_empty() {
            return Err(invalid_voice("voice consent event needs a purpose"));
        }
        let mut seen: Vec<&VoicePrintPurpose> = Vec::with_capacity(self.purposes.len());
        for purpose in &self.purposes {
            if seen.contains(&purpose) {
                return Err(invalid_voice("voice consent purposes must be distinct"));
            }
            seen.push(purpose);
        }
        self.basis.validate()
    }

    /// Returns whether this record covers `purpose`.
    #[must_use]
    pub fn covers(&self, purpose: &VoicePrintPurpose) -> bool {
        self.purposes.contains(purpose)
    }
}

/// The pinned embedding space one vector belongs to.
///
/// Family, model, revision, sample rate, dimension, and preprocessing recipe
/// together derive `space_id`. Changing any of them makes a NEW space, and
/// vectors never cross between spaces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceEmbeddingSpaceV1 {
    pub family: VoiceEmbeddingFamily,
    pub model_id: String,
    pub model_revision: String,
    pub sample_rate: u32,
    pub dimension: usize,
    pub preprocessing: String,
    pub space_id: String,
}

impl VoiceEmbeddingSpaceV1 {
    /// Builds a space with its derived `space_id`.
    pub fn new(
        family: VoiceEmbeddingFamily,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        sample_rate: u32,
        dimension: usize,
        preprocessing: impl Into<String>,
    ) -> Result<Self> {
        let space = Self {
            family,
            model_id: model_id.into(),
            model_revision: model_revision.into(),
            sample_rate,
            dimension,
            preprocessing: preprocessing.into(),
            space_id: String::new(),
        };
        let space = Self {
            space_id: space.derived_space_id(),
            ..space
        };
        space.validate()?;
        Ok(space)
    }

    /// Recomputes the `space_id` this space's fields imply.
    #[must_use]
    pub fn derived_space_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"oneiron.voice_identity.space.v1");
        for field in [
            self.family.as_str(),
            self.model_id.as_str(),
            self.model_revision.as_str(),
            self.preprocessing.as_str(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(u64::from(self.sample_rate).to_be_bytes());
        hasher.update((self.dimension as u64).to_be_bytes());
        bytes_to_hex_lower(&hasher.finalize())
    }

    /// Validates the space and verifies that `space_id` matches its fields.
    pub fn validate(&self) -> Result<()> {
        require_non_empty(&self.model_id, "voice embedding model id")?;
        require_non_empty(&self.model_revision, "voice embedding model revision")?;
        require_non_empty(&self.preprocessing, "voice embedding preprocessing")?;
        if self.sample_rate == 0 {
            return Err(invalid_voice(
                "voice embedding sample rate must be positive",
            ));
        }
        if self.dimension == 0 {
            return Err(invalid_voice("voice embedding dimension must be positive"));
        }
        if self.space_id != self.derived_space_id() {
            return Err(invalid_voice(
                "voice embedding space_id does not match its fields",
            ));
        }
        Ok(())
    }
}

/// One consented enrollment sample and its embedding.
///
/// The vector, its provenance, its language tag, and the source hash are
/// stored. The source audio itself never is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceEnrollmentSampleV1 {
    pub sample_id: String,
    pub source_ref: String,
    /// ISO language tag of the sample, e.g. `ja`, `en`, `uk`, `ru`.
    pub language: String,
    pub origin: VoiceEnrollmentOrigin,
    pub duration_ms: u64,
    pub source_sha256: String,
    pub vector: Vec<f32>,
}

/// Request to build or rebuild one subject's active voice print.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceEnrollmentRequest {
    pub subject_ref: EntityId,
    pub contact_ref: Option<EntityId>,
    pub relationship_ref: Option<EntityId>,
    pub consent_event_ref: String,
    pub purpose: VoicePrintPurpose,
    pub space: VoiceEmbeddingSpaceV1,
    pub samples: Vec<VoiceEnrollmentSampleV1>,
    pub requested_at: u64,
}

/// Request to resolve one voice session's diarized segments.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceMatchRequest {
    pub voice_session_ref: String,
    pub recording_id: String,
    pub space_id: String,
    pub segments: Vec<VoiceSegmentEmbeddingInput>,
    pub invite_attendee_refs: Vec<EntityId>,
    pub policy: VoiceMatchPolicy,
    pub created_at: u64,
}

/// Request to withdraw consent and hard-delete a subject's biometric rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceWithdrawalRequest {
    pub event_id: String,
    pub subject_ref: EntityId,
    pub recorded_by_ref: EntityId,
    pub occurred_at: u64,
    pub purposes: Vec<VoicePrintPurpose>,
    pub basis: VoiceConsentBasis,
}

/// What one withdrawal transaction actually removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceWithdrawalReceipt {
    pub consent_event_ref: String,
    pub subject_ref: EntityId,
    pub already_absent: bool,
    pub deleted_print: bool,
    pub deleted_sample_count: usize,
    pub deleted_vector_count: usize,
    pub deleted_active_pointer: bool,
}

/// One subject's stored centroid and its enrollment provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct VoicePrintRecordV1 {
    pub subject_ref: EntityId,
    pub contact_ref: Option<EntityId>,
    pub relationship_ref: Option<EntityId>,
    pub consent_event_ref: String,
    pub space: VoiceEmbeddingSpaceV1,
    pub centroid: Vec<f32>,
    pub sample_ids: Vec<String>,
    pub sample_languages: Vec<String>,
    pub calibration: VoicePrintCalibration,
    pub created_at: u64,
    pub updated_at: u64,
    pub delete_after: Option<u64>,
}

/// One diarized segment embedding offered for matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceSegmentEmbeddingInput {
    pub segment_id: String,
    pub diarization_label: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub space_id: String,
    pub vector: Vec<f32>,
}

/// The two recorded thresholds one match run used.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceMatchPolicy {
    /// Known-speaker acceptance threshold; must be in
    /// `VOICE_MATCH_THRESHOLD_MIN..=VOICE_MATCH_THRESHOLD_MAX`.
    pub known_threshold: f32,
    /// Linkage threshold for residual-only clustering.
    pub residual_threshold: f32,
}

impl VoiceMatchPolicy {
    /// Policy at this ticket's default known-speaker threshold.
    #[must_use]
    pub const fn with_known_default(residual_threshold: f32) -> Self {
        Self {
            known_threshold: VOICE_MATCH_THRESHOLD_DEFAULT,
            residual_threshold,
        }
    }

    /// Validates both thresholds against the accepted ranges.
    pub fn validate(&self) -> Result<()> {
        if !self.known_threshold.is_finite()
            || self.known_threshold < VOICE_MATCH_THRESHOLD_MIN
            || self.known_threshold > VOICE_MATCH_THRESHOLD_MAX
        {
            return Err(invalid_voice(
                "voice known_threshold must be within 0.55..=0.75",
            ));
        }
        if !self.residual_threshold.is_finite()
            || self.residual_threshold <= 0.0
            || self.residual_threshold > 1.0
        {
            return Err(invalid_voice(
                "voice residual_threshold must be within (0.0, 1.0]",
            ));
        }
        Ok(())
    }
}

/// Why one segment carries the speaker reference it carries.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceAttributionEvidence {
    /// Biometric: a cosine score at or above the recorded known threshold.
    EnrolledPrint {
        subject_ref: EntityId,
        score: f32,
        calibration: VoicePrintCalibration,
    },
    /// Non-biometric: the unique remaining invite attendee.
    InviteElimination { attendee_ref: EntityId },
    /// Anonymous: a residual cluster with a stable local label.
    ResidualCluster { cluster_ref: String },
}

/// One resolved segment of a voice session. Carries no embedding vector.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceResolvedSegment {
    pub segment_id: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub speaker_label: String,
    pub subject_ref: Option<EntityId>,
    pub contact_ref: Option<EntityId>,
    pub evidence: VoiceAttributionEvidence,
}

/// The stored, vector-free result of one match run.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceSessionRosterV1 {
    pub voice_session_ref: String,
    pub recording_id: String,
    pub embedding_space_id: String,
    pub known_threshold: f32,
    pub segments: Vec<VoiceResolvedSegment>,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Errors and small validators
// ---------------------------------------------------------------------------

fn invalid_voice(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn corrupt_voice_row() -> Error {
    Error::CorruptedIndex("voice identity record")
}

fn require_non_empty(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_voice(&format!("{what} must be non-empty")));
    }
    Ok(())
}

fn require_sha256_hex(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(invalid_voice(
            "voice enrollment source_sha256 must be 64 hex characters",
        ))
    }
}

// ---------------------------------------------------------------------------
// Vector math
// ---------------------------------------------------------------------------

/// Rejects a vector whose length, finiteness, or magnitude makes it unusable.
///
/// A zero-magnitude vector has no direction, so it can neither be normalized
/// nor compared; it is rejected on the same footing as a non-finite one.
fn validate_voice_vector(vector: &[f32], dimension: usize) -> Result<()> {
    if vector.len() != dimension {
        return Err(Error::DimensionMismatch {
            expected: dimension,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(vector) {
        return Err(error);
    }
    if squared_norm(vector) == 0.0 {
        return Err(Error::InvalidVector {
            index: 0,
            value: vector.first().copied().unwrap_or(0.0),
        });
    }
    Ok(())
}

fn squared_norm(vector: &[f32]) -> f64 {
    vector
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum()
}

/// L2-normalizes a validated vector.
fn l2_normalize(vector: &[f32], dimension: usize) -> Result<Vec<f32>> {
    validate_voice_vector(vector, dimension)?;
    let norm = squared_norm(vector).sqrt();
    let normalized: Vec<f32> = vector
        .iter()
        .map(|value| (f64::from(*value) / norm) as f32)
        .collect();
    validate_voice_vector(&normalized, dimension)?;
    Ok(normalized)
}

/// Cosine similarity of two already-normalized, equal-length vectors.
fn cosine_similarity(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(Error::DimensionMismatch {
            expected: left.len(),
            got: right.len(),
        });
    }
    let dot: f64 = left
        .iter()
        .zip(right.iter())
        .map(|(a, b)| f64::from(*a) * f64::from(*b))
        .sum();
    let score = dot.clamp(-1.0, 1.0) as f32;
    if score.is_finite() {
        Ok(score)
    } else {
        Err(Error::InvalidVector {
            index: 0,
            value: score,
        })
    }
}

/// The ONE comparison door.
///
/// Two vectors may be compared only when they belong to the identical
/// embedding space. A cross-space request is an error, never a low score, so a
/// re-pinned model can never be silently scored against an old centroid.
fn voice_cosine_in_space(
    left_space_id: &str,
    left: &[f32],
    right_space_id: &str,
    right: &[f32],
) -> Result<f32> {
    if left_space_id != right_space_id {
        return Err(invalid_voice(
            "cross-space voice comparison rejected: embedding space_id differs",
        ));
    }
    cosine_similarity(left, right)
}

// ---------------------------------------------------------------------------
// Key families
// ---------------------------------------------------------------------------

fn digest16(domain: &[u8], value: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn key_with(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    key.extend_from_slice(prefix);
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

/// Prefix covering every print-family row of one subject.
fn voice_subject_prefix(subject: &EntityId) -> Vec<u8> {
    key_with(VOICE_PRINT_KEY_PREFIX, &[subject.as_bytes()])
}

/// Active-space pointer row: subject -> active space digest.
fn voice_active_pointer_key(subject: &EntityId) -> Vec<u8> {
    voice_subject_prefix(subject)
}

/// Print row: one centroid for one (subject, embedding space).
fn voice_print_key(subject: &EntityId, space_id: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.space", space_id.as_bytes());
    key_with(VOICE_PRINT_KEY_PREFIX, &[subject.as_bytes(), &digest])
}

fn voice_sample_key(subject: &EntityId, sample_id: &str) -> Vec<u8> {
    let mut scoped = Vec::with_capacity(ENTITY_ID_LEN + sample_id.len());
    scoped.extend_from_slice(subject.as_bytes());
    scoped.extend_from_slice(sample_id.as_bytes());
    let digest = digest16(b"voice_identity.sample", &scoped);
    key_with(VOICE_SAMPLE_KEY_PREFIX, &[&digest])
}

fn voice_consent_prefix(subject: &EntityId) -> Vec<u8> {
    key_with(VOICE_CONSENT_KEY_PREFIX, &[subject.as_bytes()])
}

fn voice_consent_key(subject: &EntityId, event_id: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.consent", event_id.as_bytes());
    key_with(VOICE_CONSENT_KEY_PREFIX, &[subject.as_bytes(), &digest])
}

fn voice_roster_key(voice_session_ref: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.roster", voice_session_ref.as_bytes());
    key_with(VOICE_ROSTER_KEY_PREFIX, &[&digest])
}

// ---------------------------------------------------------------------------
// MessagePack codecs
//
// Records that carry an `EntityId` use explicit encoders/decoders with exactly
// 16-byte binary id values, so no serde impl is added to `EntityId`. Every
// decoder rejects unknown keys, duplicate keys, a wrong schema version,
// non-finite floats, and malformed ids before a record is exposed.
// ---------------------------------------------------------------------------

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_KIND: &str = "kind";

const CONSENT_KEYS: [&str; 8] = [
    KEY_SCHEMA_VERSION,
    "event_id",
    "subject_ref",
    "recorded_by_ref",
    "occurred_at",
    "purposes",
    "basis",
    "state",
];

const SPACE_KEYS: [&str; 7] = [
    "family",
    "model_id",
    "model_revision",
    "sample_rate",
    "dimension",
    "preprocessing",
    "space_id",
];

const SAMPLE_KEYS: [&str; 8] = [
    KEY_SCHEMA_VERSION,
    "sample_id",
    "source_ref",
    "language",
    "origin",
    "duration_ms",
    "source_sha256",
    "vector",
];

const PRINT_KEYS: [&str; 13] = [
    KEY_SCHEMA_VERSION,
    "subject_ref",
    "contact_ref",
    "relationship_ref",
    "consent_event_ref",
    "space",
    "centroid",
    "sample_ids",
    "sample_languages",
    "calibration",
    "created_at",
    "updated_at",
    "delete_after",
];

const ROSTER_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    "voice_session_ref",
    "recording_id",
    "embedding_space_id",
    "known_threshold",
    "segments",
    "created_at",
];

const SEGMENT_KEYS: [&str; 7] = [
    "segment_id",
    "start_ms",
    "end_ms",
    "speaker_label",
    "subject_ref",
    "contact_ref",
    "evidence",
];

const ORIGIN_SOLO_KEYS: [&str; 3] = [KEY_KIND, "session_ref", "speaker_count"];
const ORIGIN_SEGMENT_KEYS: [&str; 3] = [KEY_KIND, "recording_ref", "segment_id"];
const BASIS_NOTICE_KEYS: [&str; 2] = [KEY_KIND, "notice"];
const BASIS_VERBAL_KEYS: [&str; 5] = [KEY_KIND, "recording_ref", "start_ms", "end_ms", "words"];
const BASIS_TOGGLE_KEYS: [&str; 2] = [KEY_KIND, "surface_ref"];
const EVIDENCE_ENROLLED_KEYS: [&str; 4] = [KEY_KIND, "subject_ref", "score", "calibration"];
const EVIDENCE_INVITE_KEYS: [&str; 2] = [KEY_KIND, "attendee_ref"];
const EVIDENCE_RESIDUAL_KEYS: [&str; 2] = [KEY_KIND, "cluster_ref"];

const ORIGIN_KIND_SOLO: &str = "authenticated_solo_session";
const ORIGIN_KIND_SEGMENT: &str = "consented_diarized_segment";
const BASIS_KIND_NOTICE: &str = "conversational_notice";
const BASIS_KIND_VERBAL: &str = "verbal_on_recording";
const BASIS_KIND_TOGGLE: &str = "settings_toggle";
const EVIDENCE_KIND_ENROLLED: &str = "enrolled_print";
const EVIDENCE_KIND_INVITE: &str = "invite_elimination";
const EVIDENCE_KIND_RESIDUAL: &str = "residual_cluster";

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(corrupt_voice_row)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(corrupt_voice_row());
        };
        if seen[index] {
            return Err(corrupt_voice_row());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(corrupt_voice_row())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(corrupt_voice_row)
}

fn map_entries(value: &Value) -> Result<&Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(corrupt_voice_row()),
    }
}

fn decode_str(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(corrupt_voice_row)
}

fn decode_u64(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(corrupt_voice_row)
}

fn decode_u32(value: &Value) -> Result<u32> {
    u32::try_from(decode_u64(value)?).map_err(|_| corrupt_voice_row())
}

fn decode_usize(value: &Value) -> Result<usize> {
    usize::try_from(decode_u64(value)?).map_err(|_| corrupt_voice_row())
}

fn decode_f32(value: &Value) -> Result<f32> {
    match value {
        Value::F32(inner) if inner.is_finite() => Ok(*inner),
        _ => Err(corrupt_voice_row()),
    }
}

fn encode_entity_ref(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

/// An id is exactly one wire shape: a 16-byte MessagePack BINARY value.
///
/// A MessagePack string of the same length is a second, non-canonical form
/// this module's encoder never emits, so it is a corrupt row rather than an
/// id — the sibling record codecs match `Value::Binary` the same way.
fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(corrupt_voice_row());
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_voice_row())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt_voice_row())
}

fn encode_optional_entity_ref(id: Option<&EntityId>) -> Value {
    id.map_or(Value::Nil, encode_entity_ref)
}

fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

fn encode_vector(vector: &[f32]) -> Value {
    Value::Array(vector.iter().copied().map(Value::F32).collect())
}

fn decode_vector(value: &Value) -> Result<Vec<f32>> {
    let items = value.as_array().ok_or_else(corrupt_voice_row)?;
    items.iter().map(decode_f32).collect()
}

fn encode_string_list(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|item| Value::from(item.clone()))
            .collect(),
    )
}

fn decode_string_list(value: &Value) -> Result<Vec<String>> {
    let items = value.as_array().ok_or_else(corrupt_voice_row)?;
    items.iter().map(decode_str).collect()
}

fn encode_schema_version() -> (Value, Value) {
    (
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(VOICE_IDENTITY_SCHEMA_VERSION),
    )
}

fn require_schema_version(entries: &[(Value, Value)]) -> Result<()> {
    if decode_u64(required_value(entries, KEY_SCHEMA_VERSION)?)? == VOICE_IDENTITY_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(corrupt_voice_row())
    }
}

fn write_body(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("voice identity record encode failed"))?;
    Ok(out)
}

fn read_body(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt_voice_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt_voice_row());
    }
    Ok(value)
}

fn encode_origin(origin: &VoiceEnrollmentOrigin) -> Value {
    match origin {
        VoiceEnrollmentOrigin::AuthenticatedSoloSession {
            session_ref,
            speaker_count,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(ORIGIN_KIND_SOLO)),
            (
                Value::from(ORIGIN_SOLO_KEYS[1]),
                Value::from(session_ref.clone()),
            ),
            (
                Value::from(ORIGIN_SOLO_KEYS[2]),
                Value::from(u64::from(*speaker_count)),
            ),
        ]),
        VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
            recording_ref,
            segment_id,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(ORIGIN_KIND_SEGMENT)),
            (
                Value::from(ORIGIN_SEGMENT_KEYS[1]),
                Value::from(recording_ref.clone()),
            ),
            (
                Value::from(ORIGIN_SEGMENT_KEYS[2]),
                Value::from(segment_id.clone()),
            ),
        ]),
    }
}

/// Sample rows are written by enrollment and removed wholesale by withdrawal;
/// nothing in the production path re-reads one, so the decode half exists for
/// the round-trip and rejection gates that pin the on-disk shape.
#[cfg_attr(not(test), allow(dead_code))]
fn decode_origin(value: &Value) -> Result<VoiceEnrollmentOrigin> {
    let entries = map_entries(value)?;
    match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        ORIGIN_KIND_SOLO => {
            validate_keys(entries, &ORIGIN_SOLO_KEYS)?;
            Ok(VoiceEnrollmentOrigin::AuthenticatedSoloSession {
                session_ref: decode_str(required_value(entries, ORIGIN_SOLO_KEYS[1])?)?,
                speaker_count: decode_u32(required_value(entries, ORIGIN_SOLO_KEYS[2])?)?,
            })
        }
        ORIGIN_KIND_SEGMENT => {
            validate_keys(entries, &ORIGIN_SEGMENT_KEYS)?;
            Ok(VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
                recording_ref: decode_str(required_value(entries, ORIGIN_SEGMENT_KEYS[1])?)?,
                segment_id: decode_str(required_value(entries, ORIGIN_SEGMENT_KEYS[2])?)?,
            })
        }
        _ => Err(corrupt_voice_row()),
    }
}

fn encode_basis(basis: &VoiceConsentBasis) -> Value {
    match basis {
        VoiceConsentBasis::ConversationalNotice { notice } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_NOTICE)),
            (
                Value::from(BASIS_NOTICE_KEYS[1]),
                Value::from(notice.clone()),
            ),
        ]),
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref,
            start_ms,
            end_ms,
            words,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_VERBAL)),
            (
                Value::from(BASIS_VERBAL_KEYS[1]),
                Value::from(recording_ref.clone()),
            ),
            (Value::from(BASIS_VERBAL_KEYS[2]), Value::from(*start_ms)),
            (Value::from(BASIS_VERBAL_KEYS[3]), Value::from(*end_ms)),
            (
                Value::from(BASIS_VERBAL_KEYS[4]),
                Value::from(words.clone()),
            ),
        ]),
        VoiceConsentBasis::SettingsToggle { surface_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_TOGGLE)),
            (
                Value::from(BASIS_TOGGLE_KEYS[1]),
                Value::from(surface_ref.clone()),
            ),
        ]),
    }
}

fn decode_basis(value: &Value) -> Result<VoiceConsentBasis> {
    let entries = map_entries(value)?;
    let basis = match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        BASIS_KIND_NOTICE => {
            validate_keys(entries, &BASIS_NOTICE_KEYS)?;
            VoiceConsentBasis::ConversationalNotice {
                notice: decode_str(required_value(entries, BASIS_NOTICE_KEYS[1])?)?,
            }
        }
        BASIS_KIND_VERBAL => {
            validate_keys(entries, &BASIS_VERBAL_KEYS)?;
            VoiceConsentBasis::VerbalOnRecording {
                recording_ref: decode_str(required_value(entries, BASIS_VERBAL_KEYS[1])?)?,
                start_ms: decode_u64(required_value(entries, BASIS_VERBAL_KEYS[2])?)?,
                end_ms: decode_u64(required_value(entries, BASIS_VERBAL_KEYS[3])?)?,
                words: decode_str(required_value(entries, BASIS_VERBAL_KEYS[4])?)?,
            }
        }
        BASIS_KIND_TOGGLE => {
            validate_keys(entries, &BASIS_TOGGLE_KEYS)?;
            VoiceConsentBasis::SettingsToggle {
                surface_ref: decode_str(required_value(entries, BASIS_TOGGLE_KEYS[1])?)?,
            }
        }
        _ => return Err(corrupt_voice_row()),
    };
    basis.validate().map_err(|_| corrupt_voice_row())?;
    Ok(basis)
}

fn encode_space(space: &VoiceEmbeddingSpaceV1) -> Value {
    Value::Map(vec![
        (
            Value::from(SPACE_KEYS[0]),
            Value::from(space.family.as_str()),
        ),
        (
            Value::from(SPACE_KEYS[1]),
            Value::from(space.model_id.clone()),
        ),
        (
            Value::from(SPACE_KEYS[2]),
            Value::from(space.model_revision.clone()),
        ),
        (
            Value::from(SPACE_KEYS[3]),
            Value::from(u64::from(space.sample_rate)),
        ),
        (
            Value::from(SPACE_KEYS[4]),
            Value::from(space.dimension as u64),
        ),
        (
            Value::from(SPACE_KEYS[5]),
            Value::from(space.preprocessing.clone()),
        ),
        (
            Value::from(SPACE_KEYS[6]),
            Value::from(space.space_id.clone()),
        ),
    ])
}

fn decode_space(value: &Value) -> Result<VoiceEmbeddingSpaceV1> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SPACE_KEYS)?;
    let space = VoiceEmbeddingSpaceV1 {
        family: decode_str(required_value(entries, SPACE_KEYS[0])?)
            .ok()
            .as_deref()
            .and_then(VoiceEmbeddingFamily::parse)
            .ok_or_else(corrupt_voice_row)?,
        model_id: decode_str(required_value(entries, SPACE_KEYS[1])?)?,
        model_revision: decode_str(required_value(entries, SPACE_KEYS[2])?)?,
        sample_rate: decode_u32(required_value(entries, SPACE_KEYS[3])?)?,
        dimension: decode_usize(required_value(entries, SPACE_KEYS[4])?)?,
        preprocessing: decode_str(required_value(entries, SPACE_KEYS[5])?)?,
        space_id: decode_str(required_value(entries, SPACE_KEYS[6])?)?,
    };
    // Law 4: a stored space always re-derives its own id.
    space.validate().map_err(|_| corrupt_voice_row())?;
    Ok(space)
}

fn encode_consent_event(event: &VoiceConsentEventV1) -> Result<Vec<u8>> {
    event.validate()?;
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(CONSENT_KEYS[1]),
            Value::from(event.event_id.clone()),
        ),
        (
            Value::from(CONSENT_KEYS[2]),
            encode_entity_ref(&event.subject_ref),
        ),
        (
            Value::from(CONSENT_KEYS[3]),
            encode_entity_ref(&event.recorded_by_ref),
        ),
        (Value::from(CONSENT_KEYS[4]), Value::from(event.occurred_at)),
        (
            Value::from(CONSENT_KEYS[5]),
            Value::Array(
                event
                    .purposes
                    .iter()
                    .map(|purpose| Value::from(purpose.as_str()))
                    .collect(),
            ),
        ),
        (Value::from(CONSENT_KEYS[6]), encode_basis(&event.basis)),
        (
            Value::from(CONSENT_KEYS[7]),
            Value::from(event.state.as_str()),
        ),
    ]);
    write_body(&value)
}

fn decode_consent_event(bytes: &[u8]) -> Result<VoiceConsentEventV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &CONSENT_KEYS)?;
    require_schema_version(entries)?;

    let purposes = required_value(entries, CONSENT_KEYS[5])?
        .as_array()
        .ok_or_else(corrupt_voice_row)?
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(VoicePrintPurpose::parse)
                .ok_or_else(corrupt_voice_row)
        })
        .collect::<Result<Vec<_>>>()?;

    let event = VoiceConsentEventV1 {
        event_id: decode_str(required_value(entries, CONSENT_KEYS[1])?)?,
        subject_ref: decode_entity_ref(required_value(entries, CONSENT_KEYS[2])?)?,
        recorded_by_ref: decode_entity_ref(required_value(entries, CONSENT_KEYS[3])?)?,
        occurred_at: decode_u64(required_value(entries, CONSENT_KEYS[4])?)?,
        purposes,
        basis: decode_basis(required_value(entries, CONSENT_KEYS[6])?)?,
        state: decode_str(required_value(entries, CONSENT_KEYS[7])?)
            .ok()
            .as_deref()
            .and_then(VoiceConsentState::parse)
            .ok_or_else(corrupt_voice_row)?,
    };
    event.validate().map_err(|_| corrupt_voice_row())?;
    Ok(event)
}

fn encode_sample(sample: &VoiceEnrollmentSampleV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(SAMPLE_KEYS[1]),
            Value::from(sample.sample_id.clone()),
        ),
        (
            Value::from(SAMPLE_KEYS[2]),
            Value::from(sample.source_ref.clone()),
        ),
        (
            Value::from(SAMPLE_KEYS[3]),
            Value::from(sample.language.clone()),
        ),
        (Value::from(SAMPLE_KEYS[4]), encode_origin(&sample.origin)),
        (Value::from(SAMPLE_KEYS[5]), Value::from(sample.duration_ms)),
        (
            Value::from(SAMPLE_KEYS[6]),
            Value::from(sample.source_sha256.clone()),
        ),
        (Value::from(SAMPLE_KEYS[7]), encode_vector(&sample.vector)),
    ]);
    write_body(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_sample(bytes: &[u8]) -> Result<VoiceEnrollmentSampleV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &SAMPLE_KEYS)?;
    require_schema_version(entries)?;
    Ok(VoiceEnrollmentSampleV1 {
        sample_id: decode_str(required_value(entries, SAMPLE_KEYS[1])?)?,
        source_ref: decode_str(required_value(entries, SAMPLE_KEYS[2])?)?,
        language: decode_str(required_value(entries, SAMPLE_KEYS[3])?)?,
        origin: decode_origin(required_value(entries, SAMPLE_KEYS[4])?)?,
        duration_ms: decode_u64(required_value(entries, SAMPLE_KEYS[5])?)?,
        source_sha256: decode_str(required_value(entries, SAMPLE_KEYS[6])?)?,
        vector: decode_vector(required_value(entries, SAMPLE_KEYS[7])?)?,
    })
}

fn encode_print_record(record: &VoicePrintRecordV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(PRINT_KEYS[1]),
            encode_entity_ref(&record.subject_ref),
        ),
        (
            Value::from(PRINT_KEYS[2]),
            encode_optional_entity_ref(record.contact_ref.as_ref()),
        ),
        (
            Value::from(PRINT_KEYS[3]),
            encode_optional_entity_ref(record.relationship_ref.as_ref()),
        ),
        (
            Value::from(PRINT_KEYS[4]),
            Value::from(record.consent_event_ref.clone()),
        ),
        (Value::from(PRINT_KEYS[5]), encode_space(&record.space)),
        (Value::from(PRINT_KEYS[6]), encode_vector(&record.centroid)),
        (
            Value::from(PRINT_KEYS[7]),
            encode_string_list(&record.sample_ids),
        ),
        (
            Value::from(PRINT_KEYS[8]),
            encode_string_list(&record.sample_languages),
        ),
        (
            Value::from(PRINT_KEYS[9]),
            Value::from(record.calibration.as_str()),
        ),
        (Value::from(PRINT_KEYS[10]), Value::from(record.created_at)),
        (Value::from(PRINT_KEYS[11]), Value::from(record.updated_at)),
        (
            Value::from(PRINT_KEYS[12]),
            record.delete_after.map_or(Value::Nil, Value::from),
        ),
    ]);
    write_body(&value)
}

fn decode_print_record(bytes: &[u8]) -> Result<VoicePrintRecordV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &PRINT_KEYS)?;
    require_schema_version(entries)?;

    let space = decode_space(required_value(entries, PRINT_KEYS[5])?)?;
    let centroid = decode_vector(required_value(entries, PRINT_KEYS[6])?)?;
    validate_voice_vector(&centroid, space.dimension).map_err(|_| corrupt_voice_row())?;

    let delete_after_value = required_value(entries, PRINT_KEYS[12])?;
    let delete_after = if matches!(delete_after_value, Value::Nil) {
        None
    } else {
        Some(decode_u64(delete_after_value)?)
    };

    Ok(VoicePrintRecordV1 {
        subject_ref: decode_entity_ref(required_value(entries, PRINT_KEYS[1])?)?,
        contact_ref: decode_optional_entity_ref(required_value(entries, PRINT_KEYS[2])?)?,
        relationship_ref: decode_optional_entity_ref(required_value(entries, PRINT_KEYS[3])?)?,
        consent_event_ref: decode_str(required_value(entries, PRINT_KEYS[4])?)?,
        space,
        centroid,
        sample_ids: decode_string_list(required_value(entries, PRINT_KEYS[7])?)?,
        sample_languages: decode_string_list(required_value(entries, PRINT_KEYS[8])?)?,
        calibration: decode_str(required_value(entries, PRINT_KEYS[9])?)
            .ok()
            .as_deref()
            .and_then(VoicePrintCalibration::parse)
            .ok_or_else(corrupt_voice_row)?,
        created_at: decode_u64(required_value(entries, PRINT_KEYS[10])?)?,
        updated_at: decode_u64(required_value(entries, PRINT_KEYS[11])?)?,
        delete_after,
    })
}

fn encode_evidence(evidence: &VoiceAttributionEvidence) -> Value {
    match evidence {
        VoiceAttributionEvidence::EnrolledPrint {
            subject_ref,
            score,
            calibration,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_ENROLLED)),
            (
                Value::from(EVIDENCE_ENROLLED_KEYS[1]),
                encode_entity_ref(subject_ref),
            ),
            (Value::from(EVIDENCE_ENROLLED_KEYS[2]), Value::F32(*score)),
            (
                Value::from(EVIDENCE_ENROLLED_KEYS[3]),
                Value::from(calibration.as_str()),
            ),
        ]),
        VoiceAttributionEvidence::InviteElimination { attendee_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_INVITE)),
            (
                Value::from(EVIDENCE_INVITE_KEYS[1]),
                encode_entity_ref(attendee_ref),
            ),
        ]),
        VoiceAttributionEvidence::ResidualCluster { cluster_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_RESIDUAL)),
            (
                Value::from(EVIDENCE_RESIDUAL_KEYS[1]),
                Value::from(cluster_ref.clone()),
            ),
        ]),
    }
}

fn decode_evidence(value: &Value) -> Result<VoiceAttributionEvidence> {
    let entries = map_entries(value)?;
    match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        EVIDENCE_KIND_ENROLLED => {
            validate_keys(entries, &EVIDENCE_ENROLLED_KEYS)?;
            Ok(VoiceAttributionEvidence::EnrolledPrint {
                subject_ref: decode_entity_ref(required_value(
                    entries,
                    EVIDENCE_ENROLLED_KEYS[1],
                )?)?,
                score: decode_f32(required_value(entries, EVIDENCE_ENROLLED_KEYS[2])?)?,
                calibration: decode_str(required_value(entries, EVIDENCE_ENROLLED_KEYS[3])?)
                    .ok()
                    .as_deref()
                    .and_then(VoicePrintCalibration::parse)
                    .ok_or_else(corrupt_voice_row)?,
            })
        }
        EVIDENCE_KIND_INVITE => {
            validate_keys(entries, &EVIDENCE_INVITE_KEYS)?;
            Ok(VoiceAttributionEvidence::InviteElimination {
                attendee_ref: decode_entity_ref(required_value(entries, EVIDENCE_INVITE_KEYS[1])?)?,
            })
        }
        EVIDENCE_KIND_RESIDUAL => {
            validate_keys(entries, &EVIDENCE_RESIDUAL_KEYS)?;
            Ok(VoiceAttributionEvidence::ResidualCluster {
                cluster_ref: decode_str(required_value(entries, EVIDENCE_RESIDUAL_KEYS[1])?)?,
            })
        }
        _ => Err(corrupt_voice_row()),
    }
}

fn encode_resolved_segment(segment: &VoiceResolvedSegment) -> Value {
    Value::Map(vec![
        (
            Value::from(SEGMENT_KEYS[0]),
            Value::from(segment.segment_id.clone()),
        ),
        (Value::from(SEGMENT_KEYS[1]), Value::from(segment.start_ms)),
        (Value::from(SEGMENT_KEYS[2]), Value::from(segment.end_ms)),
        (
            Value::from(SEGMENT_KEYS[3]),
            Value::from(segment.speaker_label.clone()),
        ),
        (
            Value::from(SEGMENT_KEYS[4]),
            encode_optional_entity_ref(segment.subject_ref.as_ref()),
        ),
        (
            Value::from(SEGMENT_KEYS[5]),
            encode_optional_entity_ref(segment.contact_ref.as_ref()),
        ),
        (
            Value::from(SEGMENT_KEYS[6]),
            encode_evidence(&segment.evidence),
        ),
    ])
}

fn decode_resolved_segment(value: &Value) -> Result<VoiceResolvedSegment> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SEGMENT_KEYS)?;
    Ok(VoiceResolvedSegment {
        segment_id: decode_str(required_value(entries, SEGMENT_KEYS[0])?)?,
        start_ms: decode_u64(required_value(entries, SEGMENT_KEYS[1])?)?,
        end_ms: decode_u64(required_value(entries, SEGMENT_KEYS[2])?)?,
        speaker_label: decode_str(required_value(entries, SEGMENT_KEYS[3])?)?,
        subject_ref: decode_optional_entity_ref(required_value(entries, SEGMENT_KEYS[4])?)?,
        contact_ref: decode_optional_entity_ref(required_value(entries, SEGMENT_KEYS[5])?)?,
        evidence: decode_evidence(required_value(entries, SEGMENT_KEYS[6])?)?,
    })
}

fn encode_roster(roster: &VoiceSessionRosterV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(ROSTER_KEYS[1]),
            Value::from(roster.voice_session_ref.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[2]),
            Value::from(roster.recording_id.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[3]),
            Value::from(roster.embedding_space_id.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[4]),
            Value::F32(roster.known_threshold),
        ),
        (
            Value::from(ROSTER_KEYS[5]),
            Value::Array(
                roster
                    .segments
                    .iter()
                    .map(encode_resolved_segment)
                    .collect(),
            ),
        ),
        (Value::from(ROSTER_KEYS[6]), Value::from(roster.created_at)),
    ]);
    write_body(&value)
}

fn decode_roster(bytes: &[u8]) -> Result<VoiceSessionRosterV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &ROSTER_KEYS)?;
    require_schema_version(entries)?;
    let segments = required_value(entries, ROSTER_KEYS[5])?
        .as_array()
        .ok_or_else(corrupt_voice_row)?
        .iter()
        .map(decode_resolved_segment)
        .collect::<Result<Vec<_>>>()?;
    Ok(VoiceSessionRosterV1 {
        voice_session_ref: decode_str(required_value(entries, ROSTER_KEYS[1])?)?,
        recording_id: decode_str(required_value(entries, ROSTER_KEYS[2])?)?,
        embedding_space_id: decode_str(required_value(entries, ROSTER_KEYS[3])?)?,
        known_threshold: decode_f32(required_value(entries, ROSTER_KEYS[4])?)?,
        segments,
        created_at: decode_u64(required_value(entries, ROSTER_KEYS[6])?)?,
    })
}

// ---------------------------------------------------------------------------
// Sidecar row access
// ---------------------------------------------------------------------------

fn collect_prefix_rows(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, value) = row?;
        rows.push((key.into_owned(), value.into_owned()));
    }
    Ok(rows)
}

fn read_consent_event(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
    event_id: &str,
) -> Result<Option<VoiceConsentEventV1>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &voice_consent_key(subject, event_id))?
    else {
        return Ok(None);
    };
    decode_consent_event(&bytes).map(Some)
}

fn read_consent_events(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<VoiceConsentEventV1>> {
    collect_prefix_rows(store, rtxn, &voice_consent_prefix(subject))?
        .iter()
        .map(|(_, bytes)| decode_consent_event(bytes))
        .collect()
}

/// Reads the subject's ACTIVE print row through the active-space pointer.
fn read_active_print(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<Option<VoicePrintRecordV1>> {
    let Some(space_id) = store
        .vault_meta
        .get(rtxn, &voice_active_pointer_key(subject))?
    else {
        return Ok(None);
    };
    let space_id = std::str::from_utf8(&space_id).map_err(|_| corrupt_voice_row())?;
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &voice_print_key(subject, space_id))?
    else {
        return Err(corrupt_voice_row());
    };
    decode_print_record(&bytes).map(Some)
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_sample(
    store: &Store,
    rtxn: &RoTxn<'_>,
    subject: &EntityId,
    sample_id: &str,
) -> Result<Option<VoiceEnrollmentSampleV1>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &voice_sample_key(subject, sample_id))?
    else {
        return Ok(None);
    };
    decode_sample(&bytes).map(Some)
}

/// Every subject that currently has an active-space pointer, in key order.
fn active_print_subjects(store: &Store, rtxn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut subjects = Vec::new();
    for (key, _) in collect_prefix_rows(store, rtxn, VOICE_PRINT_KEY_PREFIX)? {
        if key.len() != VOICE_PRINT_KEY_PREFIX.len() + ENTITY_ID_LEN {
            continue;
        }
        let raw: [u8; ENTITY_ID_LEN] = key[VOICE_PRINT_KEY_PREFIX.len()..]
            .try_into()
            .map_err(|_| corrupt_voice_row())?;
        subjects.push(EntityId::from_bytes(raw).map_err(|_| corrupt_voice_row())?);
    }
    Ok(subjects)
}

/// What one biometric deletion transaction removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct VoiceDeletionTally {
    print_rows: usize,
    sample_rows: usize,
    vector_rows: usize,
    active_pointer: bool,
}

impl VoiceDeletionTally {
    const fn is_empty(self) -> bool {
        self.print_rows == 0 && self.sample_rows == 0 && !self.active_pointer
    }
}

/// The ONE biometric deletion routine.
///
/// Explicit withdrawal and retention pruning share it, so both paths delete
/// exactly the same rows: every print row of the subject (each holding one
/// centroid), every sample/vector row those prints reference, and the
/// active-space pointer.
fn delete_voice_biometrics_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EntityId,
) -> Result<VoiceDeletionTally> {
    let rows = collect_prefix_rows(store, wtxn, &voice_subject_prefix(subject))?;
    let pointer_key = voice_active_pointer_key(subject);

    let mut sample_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut print_keys: Vec<Vec<u8>> = Vec::new();
    let mut tally = VoiceDeletionTally::default();

    for (key, value) in rows {
        if key == pointer_key {
            tally.active_pointer = true;
            continue;
        }
        let record = decode_print_record(&value)?;
        for sample_id in &record.sample_ids {
            sample_keys.insert(voice_sample_key(subject, sample_id));
        }
        // One print row holds exactly one centroid vector.
        tally.vector_rows = tally.vector_rows.saturating_add(1);
        print_keys.push(key);
    }

    for key in print_keys {
        if store.vault_meta.delete(wtxn, &key)? {
            tally.print_rows = tally.print_rows.saturating_add(1);
        }
    }
    for key in sample_keys {
        if store.vault_meta.delete(wtxn, &key)? {
            tally.sample_rows = tally.sample_rows.saturating_add(1);
            tally.vector_rows = tally.vector_rows.saturating_add(1);
        }
    }
    if tally.active_pointer {
        store.vault_meta.delete(wtxn, &pointer_key)?;
    }
    Ok(tally)
}

fn entity_type_in_txn(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// Law 9: a retention link must name an EXISTING RELATIONSHIP entity.
fn require_relationship_entity(
    store: &Store,
    rtxn: &RoTxn<'_>,
    relationship: &EntityId,
) -> Result<()> {
    let found = entity_type_in_txn(store, rtxn, relationship)?;
    if found == Some(ENTITY_TYPE_RELATIONSHIP) {
        Ok(())
    } else {
        Err(Error::InvalidRelationship {
            relationship: *relationship,
            found,
        })
    }
}

fn require_counterparty_contact_entity(
    store: &Store,
    rtxn: &RoTxn<'_>,
    contact: &EntityId,
) -> Result<()> {
    match entity_type_in_txn(store, rtxn, contact)? {
        Some(ENTITY_TYPE_COUNTERPARTY_CONTACT) => Ok(()),
        Some(other) => Err(Error::InvalidEntityType(other)),
        None => Err(Error::EntityNotFound),
    }
}

// ---------------------------------------------------------------------------
// Enrollment laws
// ---------------------------------------------------------------------------

/// Laws 1 and 10: consent must precede enrollment, cover the purpose, and not
/// have been withdrawn since.
fn admit_enrollment_consent(
    store: &Store,
    rtxn: &RoTxn<'_>,
    request: &VoiceEnrollmentRequest,
) -> Result<VoiceConsentEventV1> {
    let event = read_consent_event(
        store,
        rtxn,
        &request.subject_ref,
        &request.consent_event_ref,
    )?
    .ok_or_else(|| invalid_voice("voice enrollment needs a recorded consent event"))?;
    if event.state != VoiceConsentState::Granted {
        return Err(invalid_voice(
            "voice enrollment consent event is not a grant",
        ));
    }
    if !event.covers(&request.purpose) {
        return Err(invalid_voice(
            "voice enrollment consent does not cover the requested purpose",
        ));
    }
    if event.occurred_at > request.requested_at {
        return Err(invalid_voice(
            "voice enrollment consent must precede the enrollment request",
        ));
    }
    let withdrawn = read_consent_events(store, rtxn, &request.subject_ref)?
        .into_iter()
        .any(|candidate| {
            candidate.state == VoiceConsentState::Withdrawn
                && candidate.covers(&request.purpose)
                && candidate.occurred_at >= event.occurred_at
        });
    if withdrawn {
        return Err(invalid_voice(
            "voice consent for this purpose was withdrawn after the cited grant",
        ));
    }
    Ok(event)
}

/// Law 2: which provenance a sample must carry.
fn admit_sample_origin(
    sample: &VoiceEnrollmentSampleV1,
    is_contact_enrollment: bool,
    consent: &VoiceConsentEventV1,
) -> Result<()> {
    match &sample.origin {
        VoiceEnrollmentOrigin::AuthenticatedSoloSession {
            session_ref,
            speaker_count,
        } => {
            if is_contact_enrollment {
                return Err(invalid_voice(
                    "contact voice samples require a consented diarized segment",
                ));
            }
            require_non_empty(session_ref, "voice enrollment session ref")?;
            if *speaker_count != 1 {
                return Err(invalid_voice(
                    "passive principal voice samples require a solo session (speaker_count == 1)",
                ));
            }
            Ok(())
        }
        VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
            recording_ref,
            segment_id,
        } => {
            if !is_contact_enrollment {
                return Err(invalid_voice(
                    "principal voice samples require an authenticated solo session",
                ));
            }
            require_non_empty(recording_ref, "voice enrollment recording ref")?;
            require_non_empty(segment_id, "voice enrollment segment id")?;
            if sample.source_ref != *recording_ref {
                return Err(invalid_voice(
                    "voice enrollment sample source_ref must name its recording",
                ));
            }
            if consent.basis.recording_ref() != Some(recording_ref.as_str()) {
                return Err(invalid_voice(
                    "voice enrollment consent does not name this recording",
                ));
            }
            Ok(())
        }
    }
}

/// Law 3: duration-weighted mean of normalized samples, normalized again.
fn compute_centroid(samples: &[&VoiceEnrollmentSampleV1], dimension: usize) -> Result<Vec<f32>> {
    let mut accumulator = vec![0.0_f64; dimension];
    let mut total_weight = 0.0_f64;
    for sample in samples {
        let normalized = l2_normalize(&sample.vector, dimension)?;
        let weight = sample.duration_ms as f64;
        for (slot, value) in accumulator.iter_mut().zip(normalized.iter()) {
            *slot += weight * f64::from(*value);
        }
        total_weight += weight;
    }
    if total_weight <= 0.0 {
        return Err(invalid_voice(
            "voice enrollment samples need a positive total duration",
        ));
    }
    let mean: Vec<f32> = accumulator
        .iter()
        .map(|value| (*value / total_weight) as f32)
        .collect();
    l2_normalize(&mean, dimension)
}

/// Law 3: mixed-language means at least two distinct tags.
fn calibration_for(languages: &[String]) -> VoicePrintCalibration {
    let distinct: BTreeSet<&str> = languages.iter().map(String::as_str).collect();
    if distinct.len() >= VOICE_CALIBRATION_MIN_LANGUAGES {
        VoicePrintCalibration::Calibrated
    } else {
        VoicePrintCalibration::Collecting
    }
}

// ---------------------------------------------------------------------------
// Matching, clustering, invite elimination
// ---------------------------------------------------------------------------

/// One active centroid admitted as a match candidate.
#[derive(Debug, Clone)]
struct VoiceMatchCandidate {
    subject_ref: EntityId,
    contact_ref: Option<EntityId>,
    space_id: String,
    centroid: Vec<f32>,
    calibration: VoicePrintCalibration,
}

/// Validates a match request and returns its segments in canonical order,
/// every admitted vector L2-normalized at this door.
///
/// Canonical order is (start_ms, segment_id) — the Law 6 residual-label key —
/// so a caller that hands the same segments in a different order gets a
/// byte-identical roster. Segment ids are distinct, so that pair is a total
/// order.
///
/// Law 5: the comparison door is a plain dot product over already-normalized
/// vectors, and every stored-side vector is normalized. Normalizing here is
/// what makes each enrolled-match and residual-linkage score an actual cosine
/// instead of a magnitude-scaled one, so a loud segment cannot buy acceptance
/// and a quiet one cannot be rejected for its length. [`l2_normalize`] runs
/// the dimension, finiteness, and non-zero checks, so admission validation
/// folds into it. The caller's request is untouched.
fn admit_match_segments(request: &VoiceMatchRequest) -> Result<Vec<VoiceSegmentEmbeddingInput>> {
    require_non_empty(&request.voice_session_ref, "voice session ref")?;
    require_non_empty(&request.recording_id, "voice recording id")?;
    require_non_empty(&request.space_id, "voice embedding space id")?;
    request.policy.validate()?;
    if request.segments.len() > VOICE_MAX_MATCH_SEGMENTS {
        return Err(invalid_voice(
            "voice match request exceeds the supported segment count",
        ));
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(request.segments.len());
    let mut dimension: Option<usize> = None;
    let mut segments = Vec::with_capacity(request.segments.len());
    for segment in &request.segments {
        require_non_empty(&segment.segment_id, "voice segment id")?;
        if !seen.insert(segment.segment_id.as_str()) {
            return Err(invalid_voice("voice segment ids must be distinct"));
        }
        if segment.start_ms >= segment.end_ms {
            return Err(invalid_voice("voice segment needs start_ms < end_ms"));
        }
        // Law 4: a foreign-space segment is an error, never a low score.
        if segment.space_id != request.space_id {
            return Err(invalid_voice(
                "cross-space voice segment rejected: embedding space_id differs",
            ));
        }
        let declared = *dimension.get_or_insert(segment.vector.len());
        // Law 5: validate and normalize in one step; only unit-length vectors
        // are ever admitted, so every downstream score is a true cosine.
        let mut admitted = segment.clone();
        admitted.vector = l2_normalize(&segment.vector, declared)?;
        segments.push(admitted);
    }

    segments.sort_by(|left, right| {
        (left.start_ms, left.segment_id.as_str()).cmp(&(right.start_ms, right.segment_id.as_str()))
    });
    Ok(segments)
}

fn load_match_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    space_id: &str,
) -> Result<Vec<VoiceMatchCandidate>> {
    let mut candidates = Vec::new();
    for subject in active_print_subjects(store, rtxn)? {
        let Some(record) = read_active_print(store, rtxn, &subject)? else {
            continue;
        };
        if record.space.space_id != space_id {
            // A print pinned to another space is simply not a candidate here;
            // it is never compared and never scored low.
            continue;
        }
        candidates.push(VoiceMatchCandidate {
            subject_ref: record.subject_ref,
            contact_ref: record.contact_ref,
            space_id: record.space.space_id.clone(),
            centroid: l2_normalize(&record.centroid, record.space.dimension)?,
            calibration: record.calibration,
        });
    }
    // Deterministic subject-id tie-break for equal scores.
    candidates.sort_by_key(|left| left.subject_ref);
    Ok(candidates)
}

/// Law 5: highest enrolled score, subject-id tie-break, accept at threshold.
fn best_enrolled_match<'a>(
    segment_space_id: &str,
    segment_vector: &[f32],
    candidates: &'a [VoiceMatchCandidate],
    known_threshold: f32,
) -> Result<Option<(&'a VoiceMatchCandidate, f32)>> {
    let mut best: Option<(&VoiceMatchCandidate, f32)> = None;
    for candidate in candidates {
        let score = voice_cosine_in_space(
            segment_space_id,
            segment_vector,
            &candidate.space_id,
            &candidate.centroid,
        )?;
        let improves = best.is_none_or(|(_, best_score)| score > best_score);
        if improves {
            best = Some((candidate, score));
        }
    }
    Ok(best.filter(|(_, score)| *score >= known_threshold))
}

/// Law 6: single-linkage agglomerative cosine clustering of residuals only.
///
/// At a fixed linkage threshold single linkage is exactly the connected
/// components of the "cosine at or above threshold" graph, so the result does
/// not depend on merge order at all. Clusters come back ordered by their
/// earliest member in the caller's canonical segment order.
fn cluster_residuals(vectors: &[&[f32]], residual_threshold: f32) -> Result<Vec<Vec<usize>>> {
    fn find(parent: &mut [usize], mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }

    let count = vectors.len();
    let mut parent: Vec<usize> = (0..count).collect();

    for left in 0..count {
        for right in (left + 1)..count {
            if cosine_similarity(vectors[left], vectors[right])? >= residual_threshold {
                let (root_left, root_right) = (find(&mut parent, left), find(&mut parent, right));
                if root_left != root_right {
                    let (low, high) = if root_left < root_right {
                        (root_left, root_right)
                    } else {
                        (root_right, root_left)
                    };
                    parent[high] = low;
                }
            }
        }
    }

    let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..count {
        let root = find(&mut parent, index);
        clusters.entry(root).or_default().push(index);
    }
    Ok(clusters.into_values().collect())
}

/// Law 7: name the unique remaining attendee, or keep everyone anonymous.
///
/// Ambiguity is not resolved by lowering a threshold or by nudging a score;
/// it simply leaves the anonymous labels in place.
fn unambiguous_invite_remainder(
    invite_attendee_refs: &[EntityId],
    matched_refs: &BTreeSet<EntityId>,
    residual_cluster_count: usize,
) -> Option<EntityId> {
    let remaining: BTreeSet<EntityId> = invite_attendee_refs
        .iter()
        .copied()
        .filter(|attendee| !matched_refs.contains(attendee))
        .collect();
    if remaining.len() == 1 && residual_cluster_count == 1 {
        remaining.into_iter().next()
    } else {
        None
    }
}

fn residual_cluster_ref(index: usize) -> String {
    format!("residual.{}", index.saturating_add(1))
}

fn residual_speaker_label(index: usize) -> String {
    format!("anonymous speaker {}", index.saturating_add(1))
}

// ---------------------------------------------------------------------------
// Vault surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Appends one consent or withdrawal decision to the private consent log.
    ///
    /// The record carries who, when, what purposes, how consent was captured,
    /// and its evidence refs. It grants no owner authority, no outbound
    /// permission, and no disclosure widening, and it never carries a vector.
    pub fn record_voice_consent(&self, event: &VoiceConsentEventV1) -> Result<()> {
        let data = encode_consent_event(event)?;
        let key = voice_consent_key(&event.subject_ref, &event.event_id);
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, &key, &data)?;
            Ok(())
        })
    }

    /// Builds (or rebuilds) one subject's active voice print.
    ///
    /// Consent is checked first, then sample provenance, then the vectors
    /// themselves. The subject's previous print rows, their sample/vector
    /// rows, and the active-space pointer are replaced inside the same write
    /// transaction, so a re-pinned model never leaves a stale centroid behind
    /// and a rejected request writes nothing at all.
    pub fn enroll_voice_print(
        &self,
        request: &VoiceEnrollmentRequest,
    ) -> Result<VoicePrintRecordV1> {
        request.space.validate()?;
        require_non_empty(&request.consent_event_ref, "voice consent event ref")?;
        if request.samples.is_empty() {
            return Err(invalid_voice("voice enrollment needs at least one sample"));
        }

        // Deterministic accumulation order: the centroid must not depend on
        // the order the caller happened to hand the samples over in.
        let mut ordered: Vec<&VoiceEnrollmentSampleV1> = request.samples.iter().collect();
        ordered.sort_by(|left, right| left.sample_id.cmp(&right.sample_id));
        let mut seen_ids: HashSet<&str> = HashSet::with_capacity(ordered.len());
        for sample in &ordered {
            require_non_empty(&sample.sample_id, "voice sample id")?;
            require_non_empty(&sample.source_ref, "voice sample source ref")?;
            require_non_empty(&sample.language, "voice sample language")?;
            require_sha256_hex(&sample.source_sha256)?;
            if sample.duration_ms == 0 {
                return Err(invalid_voice("voice sample duration must be positive"));
            }
            if !seen_ids.insert(sample.sample_id.as_str()) {
                return Err(invalid_voice("voice sample ids must be distinct"));
            }
            validate_voice_vector(&sample.vector, request.space.dimension)?;
        }

        let is_contact_enrollment = request.contact_ref.is_some();
        let centroid = compute_centroid(&ordered, request.space.dimension)?;
        let sample_ids: Vec<String> = ordered
            .iter()
            .map(|sample| sample.sample_id.clone())
            .collect();
        let sample_languages: Vec<String> = ordered
            .iter()
            .map(|sample| sample.language.clone())
            .collect();
        let calibration = calibration_for(&sample_languages);

        let store = &self.store;
        let subject = request.subject_ref;
        self.with_write_txn(|wtxn| {
            let consent = admit_enrollment_consent(store, wtxn, request)?;
            for sample in &ordered {
                admit_sample_origin(sample, is_contact_enrollment, &consent)?;
            }
            if let Some(contact_ref) = request.contact_ref.as_ref() {
                require_counterparty_contact_entity(store, wtxn, contact_ref)?;
            }
            if let Some(relationship_ref) = request.relationship_ref.as_ref() {
                require_relationship_entity(store, wtxn, relationship_ref)?;
            }

            let previous = read_active_print(store, wtxn, &subject)?;
            delete_voice_biometrics_in_txn(store, wtxn, &subject)?;

            let record = VoicePrintRecordV1 {
                subject_ref: subject,
                contact_ref: request.contact_ref,
                relationship_ref: request.relationship_ref,
                consent_event_ref: request.consent_event_ref.clone(),
                space: request.space.clone(),
                centroid: centroid.clone(),
                sample_ids: sample_ids.clone(),
                sample_languages: sample_languages.clone(),
                calibration,
                created_at: previous.map_or(request.requested_at, |prior| prior.created_at),
                updated_at: request.requested_at,
                delete_after: None,
            };
            let body = encode_print_record(&record)?;
            store.vault_meta.put(
                wtxn,
                &voice_print_key(&subject, &request.space.space_id),
                &body,
            )?;
            store.vault_meta.put(
                wtxn,
                &voice_active_pointer_key(&subject),
                request.space.space_id.as_bytes(),
            )?;
            for sample in &ordered {
                store.vault_meta.put(
                    wtxn,
                    &voice_sample_key(&subject, &sample.sample_id),
                    &encode_sample(sample)?,
                )?;
            }
            Ok(record)
        })
    }

    /// Resolves one voice session's diarized segments into a stored roster.
    ///
    /// Enrolled principals are matched first and removed; only what is left
    /// enters residual clustering; invite elimination then names at most one
    /// unambiguous remainder. The stored roster carries labels, scores, and
    /// evidence — never an embedding vector.
    pub fn resolve_voice_segments(
        &self,
        request: &VoiceMatchRequest,
    ) -> Result<VoiceSessionRosterV1> {
        let segments = admit_match_segments(request)?;
        let known_threshold = request.policy.known_threshold;

        let rtxn = self.store.env.read_txn()?;
        let candidates = load_match_candidates(&self.store, &rtxn, &request.space_id)?;
        drop(rtxn);

        let mut resolved: Vec<Option<VoiceResolvedSegment>> = vec![None; segments.len()];
        let mut matched_refs: BTreeSet<EntityId> = BTreeSet::new();
        let mut residual_indexes: Vec<usize> = Vec::new();

        for (index, segment) in segments.iter().enumerate() {
            let matched = best_enrolled_match(
                &segment.space_id,
                &segment.vector,
                &candidates,
                known_threshold,
            )?;
            match matched {
                Some((candidate, score)) => {
                    matched_refs.insert(candidate.subject_ref);
                    if let Some(contact_ref) = candidate.contact_ref {
                        matched_refs.insert(contact_ref);
                    }
                    resolved[index] = Some(VoiceResolvedSegment {
                        segment_id: segment.segment_id.clone(),
                        start_ms: segment.start_ms,
                        end_ms: segment.end_ms,
                        speaker_label: candidate.subject_ref.to_hex(),
                        subject_ref: Some(candidate.subject_ref),
                        contact_ref: candidate.contact_ref,
                        evidence: VoiceAttributionEvidence::EnrolledPrint {
                            subject_ref: candidate.subject_ref,
                            score,
                            calibration: candidate.calibration,
                        },
                    });
                }
                None => residual_indexes.push(index),
            }
        }

        // Law 6: accepted segments are gone before clustering starts, and no
        // enrolled centroid ever participates in it.
        let residual_vectors: Vec<&[f32]> = residual_indexes
            .iter()
            .map(|index| segments[*index].vector.as_slice())
            .collect();
        let clusters = cluster_residuals(&residual_vectors, request.policy.residual_threshold)?;
        let invited = unambiguous_invite_remainder(
            &request.invite_attendee_refs,
            &matched_refs,
            clusters.len(),
        );

        for (cluster_index, members) in clusters.iter().enumerate() {
            for member in members {
                let index = residual_indexes[*member];
                let segment = &segments[index];
                let (label, subject_ref, contact_ref, evidence) = match invited {
                    Some(attendee_ref) => (
                        attendee_ref.to_hex(),
                        None,
                        Some(attendee_ref),
                        VoiceAttributionEvidence::InviteElimination { attendee_ref },
                    ),
                    None => (
                        residual_speaker_label(cluster_index),
                        None,
                        None,
                        VoiceAttributionEvidence::ResidualCluster {
                            cluster_ref: residual_cluster_ref(cluster_index),
                        },
                    ),
                };
                resolved[index] = Some(VoiceResolvedSegment {
                    segment_id: segment.segment_id.clone(),
                    start_ms: segment.start_ms,
                    end_ms: segment.end_ms,
                    speaker_label: label,
                    subject_ref,
                    contact_ref,
                    evidence,
                });
            }
        }

        // Law 8: the roster is stored only once every segment resolved.
        let segments = resolved
            .into_iter()
            .map(|entry| entry.ok_or_else(|| Error::InvariantViolation("voice segment unresolved")))
            .collect::<Result<Vec<_>>>()?;

        let roster = VoiceSessionRosterV1 {
            voice_session_ref: request.voice_session_ref.clone(),
            recording_id: request.recording_id.clone(),
            embedding_space_id: request.space_id.clone(),
            known_threshold,
            segments,
            created_at: request.created_at,
        };
        let body = encode_roster(&roster)?;
        let key = voice_roster_key(&roster.voice_session_ref);
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, &key, &body)?;
            Ok(())
        })?;
        Ok(roster)
    }

    /// Reads a stored roster. A missing roster is `Ok(None)`; a corrupt one is
    /// an error, so the interlocutor seam can fail closed on it.
    pub fn voice_session_roster(
        &self,
        voice_session_ref: &str,
    ) -> Result<Option<VoiceSessionRosterV1>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &voice_roster_key(voice_session_ref))?
        else {
            return Ok(None);
        };
        decode_roster(&bytes).map(Some)
    }

    /// Ends a voice-print retention relationship and stamps `delete_after`.
    ///
    /// The relationship must resolve to an existing RELATIONSHIP entity and
    /// must be the one the print is actually linked to. The print is retained
    /// until `ended_at + retention_secs`, then removed by
    /// [`Vault::prune_expired_voice_prints`] through the same deletion
    /// transaction explicit withdrawal uses.
    pub fn end_voice_relationship(
        &self,
        subject_ref: EntityId,
        relationship_ref: EntityId,
        ended_at: u64,
        retention_secs: u64,
    ) -> Result<()> {
        let delete_after = ended_at
            .checked_add(retention_secs)
            .ok_or(Error::ArithmeticOverflow("voice print retention deadline"))?;
        let store = &self.store;
        self.with_write_txn(|wtxn| {
            require_relationship_entity(store, wtxn, &relationship_ref)?;
            let record =
                read_active_print(store, wtxn, &subject_ref)?.ok_or(Error::EntityNotFound)?;
            if record.relationship_ref != Some(relationship_ref) {
                return Err(invalid_voice(
                    "voice print is not linked to the supplied relationship",
                ));
            }
            let updated = VoicePrintRecordV1 {
                updated_at: ended_at,
                delete_after: Some(delete_after),
                ..record
            };
            let body = encode_print_record(&updated)?;
            store.vault_meta.put(
                wtxn,
                &voice_print_key(&subject_ref, &updated.space.space_id),
                &body,
            )?;
            Ok(())
        })
    }

    /// Hard-deletes every voice print whose retention deadline has passed.
    ///
    /// Uses the same deletion transaction as explicit withdrawal, so a pruned
    /// subject and a withdrawn subject are left in exactly the same state.
    /// Returns the pruned subjects in ascending id order.
    pub fn prune_expired_voice_prints(&self, now: u64) -> Result<Vec<EntityId>> {
        let store = &self.store;
        self.with_write_txn(|wtxn| {
            let mut expired: Vec<EntityId> = Vec::new();
            for subject in active_print_subjects(store, wtxn)? {
                let Some(record) = read_active_print(store, wtxn, &subject)? else {
                    continue;
                };
                if record.delete_after.is_some_and(|deadline| deadline <= now) {
                    expired.push(subject);
                }
            }
            expired.sort_unstable();
            for subject in &expired {
                delete_voice_biometrics_in_txn(store, wtxn, subject)?;
            }
            Ok(expired)
        })
    }

    /// Withdraws consent and hard-deletes the subject's biometric material.
    ///
    /// One write transaction appends the non-biometric withdrawal event and
    /// removes the print row, every stored sample/vector row, and the
    /// active-space pointer. A second call is idempotent: nothing is left to
    /// delete, and the receipt says `already_absent`.
    pub fn withdraw_voice_consent(
        &self,
        request: &VoiceWithdrawalRequest,
    ) -> Result<VoiceWithdrawalReceipt> {
        let event = VoiceConsentEventV1 {
            event_id: request.event_id.clone(),
            subject_ref: request.subject_ref,
            recorded_by_ref: request.recorded_by_ref,
            occurred_at: request.occurred_at,
            purposes: request.purposes.clone(),
            basis: request.basis.clone(),
            state: VoiceConsentState::Withdrawn,
        };
        let body = encode_consent_event(&event)?;
        let consent_key = voice_consent_key(&event.subject_ref, &event.event_id);

        let store = &self.store;
        let subject = request.subject_ref;
        let tally = self.with_write_txn(|wtxn| {
            let tally = delete_voice_biometrics_in_txn(store, wtxn, &subject)?;
            store.vault_meta.put(wtxn, &consent_key, &body)?;
            Ok(tally)
        })?;

        Ok(VoiceWithdrawalReceipt {
            consent_event_ref: request.event_id.clone(),
            subject_ref: subject,
            already_absent: tally.is_empty(),
            deleted_print: tally.print_rows > 0,
            deleted_sample_count: tally.sample_rows,
            deleted_vector_count: tally.vector_rows,
            deleted_active_pointer: tally.active_pointer,
        })
    }
}

/// Stores a roster directly, without running a match pass.
///
/// Test-only seam for the ILD-3 interlocutor gates, which need a roster of a
/// given SHAPE (owner print, contact print, invite elimination, residual) far
/// more cheaply than a full enrollment fixture would supply one.
#[cfg(test)]
pub(crate) fn put_voice_roster_for_test(
    vault: &Vault,
    roster: &VoiceSessionRosterV1,
) -> Result<()> {
    let body = encode_roster(roster)?;
    let key = voice_roster_key(&roster.voice_session_ref);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &body)?;
        Ok(())
    })
}

/// Stores arbitrary bytes at a roster key, for the corrupt-roster gate.
#[cfg(test)]
pub(crate) fn put_raw_voice_roster_for_test(
    vault: &Vault,
    voice_session_ref: &str,
    bytes: &[u8],
) -> Result<()> {
    let key = voice_roster_key(voice_session_ref);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, bytes)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
