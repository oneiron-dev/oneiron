//! Moved from `crates/oneiron/src/voice_identity/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentBasis;
pub use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentState;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

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

/// One diarized segment embedding offered for matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceSegmentEmbeddingInput {
    pub segment_id: String,
    pub diarization_label: String,
    /// The capture's session-local key for this physical speaker: the same
    /// for every segment of that speaker in the session, never minted per
    /// segment, from a contact pick or from a voice print.
    pub speaker_key: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub space_id: String,
    pub vector: Vec<f32>,
}
