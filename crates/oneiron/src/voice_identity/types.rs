//! Public domain types, request/receipt structs, thresholds, key prefixes, and validators.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;

use super::math_keys::{invalid_voice, require_non_empty};

/// Ticket-owned default known-speaker acceptance threshold (cosine).
pub const VOICE_MATCH_THRESHOLD_DEFAULT: f32 = 0.65;

/// Lowest known-speaker threshold this engine accepts.
pub const VOICE_MATCH_THRESHOLD_MIN: f32 = 0.55;

/// Highest known-speaker threshold this engine accepts.
pub const VOICE_MATCH_THRESHOLD_MAX: f32 = 0.75;

/// Schema version stamped into every voice-identity sidecar body.
pub(super) const VOICE_IDENTITY_SCHEMA_VERSION: u64 = 1;

/// Distinct language tags a centroid needs before it is `Calibrated`.
pub(super) const VOICE_CALIBRATION_MIN_LANGUAGES: usize = 2;

/// Upper bound on segments in one match request.
///
/// Residual clustering is quadratic in the residual count; this bound keeps a
/// single request from turning into an unbounded local job. It is a
/// ticket-owned dial, not a canon-frozen constant.
pub(super) const VOICE_MAX_MATCH_SEGMENTS: usize = 1024;

/// `vault_meta` key prefix for voice print rows and the active-space pointer.
pub(super) const VOICE_PRINT_KEY_PREFIX: &[u8] = b"voice_identity.print.v1:";

/// `vault_meta` key prefix for stored enrollment sample/vector rows.
pub(super) const VOICE_SAMPLE_KEY_PREFIX: &[u8] = b"voice_identity.sample.v1:";

/// `vault_meta` key prefix for consent/withdrawal event rows.
pub(super) const VOICE_CONSENT_KEY_PREFIX: &[u8] = b"voice_identity.consent.v1:";

/// `vault_meta` key prefix for resolved session roster rows.
pub(super) const VOICE_ROSTER_KEY_PREFIX: &[u8] = b"voice_identity.roster.v1:";

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
