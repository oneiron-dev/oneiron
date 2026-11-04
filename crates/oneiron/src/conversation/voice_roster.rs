//! Vector-free voice attribution and session roster records.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

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

/// Why one segment carries the speaker reference it carries.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceAttributionEvidence {
    /// Biometric: a cosine score at or above the recorded known threshold.
    EnrolledPrint {
        subject_ref: EntityId,
        score: f32,
        calibration: VoicePrintCalibration,
        /// The exact print generation that produced this score.
        print_generation: EntityId,
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
    /// The capture's session-local speaker key, kept from the input.
    pub speaker_key: String,
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
    /// Starts at 1 and moves only when a speaker joins or is placed
    /// differently; more words, new spans or score jitter keep it. An
    /// owner's answer about a speaker holds for one revision.
    pub roster_revision: u64,
}

impl VoiceSessionRosterV1 {
    /// The speakers the roster could not place, by speaker key in the order
    /// first heard: every segment of each fell to residual clustering. These
    /// are the speakers an owner may be asked about, at this revision.
    #[must_use]
    pub fn unplaced_speakers(&self) -> Vec<&str> {
        let placed: Vec<&str> = self
            .segments
            .iter()
            .filter(|segment| {
                !matches!(
                    segment.evidence,
                    VoiceAttributionEvidence::ResidualCluster { .. }
                )
            })
            .map(|segment| segment.speaker_key.as_str())
            .collect();
        let mut unplaced: Vec<&str> = Vec::new();
        for segment in &self.segments {
            let key = segment.speaker_key.as_str();
            if !placed.contains(&key) && !unplaced.contains(&key) {
                unplaced.push(key);
            }
        }
        unplaced
    }
}
