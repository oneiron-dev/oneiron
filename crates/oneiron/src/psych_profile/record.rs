//! Snapshot record types, projections, and constructors/validators.

use super::codec::{
    canonical_source_revision_ids, invalid_profile, validate_confidence, validate_text,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Current PsychProfile record body schema version.
pub const PSYCH_PROFILE_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for PSYCH_PROFILE bodies.
pub const PSYCH_PROFILE_BODY_KEYS: [&str; 8] = [
    "schemaVersion",
    "subjectRef",
    "compact",
    "text",
    "narrative",
    "sourceRevisionIds",
    "confidence",
    "status",
];

/// Minimal projection: enough to answer "is there a profile and is it fresh?"
pub(crate) const PSYCH_PROFILE_FIELDS_MINIMAL: &[&str] =
    &["schemaVersion", "subjectRef", "sourceRevisionIds", "status"];

/// Standard projection: add the cheap compact render and confidence metadata.
pub(crate) const PSYCH_PROFILE_FIELDS_STANDARD: &[&str] = &[
    "schemaVersion",
    "subjectRef",
    "compact",
    "sourceRevisionIds",
    "confidence",
    "status",
];

/// Full projection: every persisted PsychProfile field.
pub(crate) const PSYCH_PROFILE_FIELDS_FULL: &[&str] = &PSYCH_PROFILE_BODY_KEYS;

pub(super) const KEY_SCHEMA_VERSION: &str = PSYCH_PROFILE_BODY_KEYS[0];

pub(super) const KEY_SUBJECT_REF: &str = PSYCH_PROFILE_BODY_KEYS[1];

pub(super) const KEY_COMPACT: &str = PSYCH_PROFILE_BODY_KEYS[2];

pub(super) const KEY_TEXT: &str = PSYCH_PROFILE_BODY_KEYS[3];

pub(super) const KEY_NARRATIVE: &str = PSYCH_PROFILE_BODY_KEYS[4];

pub(super) const KEY_SOURCE_REVISION_IDS: &str = PSYCH_PROFILE_BODY_KEYS[5];

pub(super) const KEY_CONFIDENCE: &str = PSYCH_PROFILE_BODY_KEYS[6];

pub(super) const KEY_STATUS: &str = PSYCH_PROFILE_BODY_KEYS[7];

pub(super) const CONFIDENCE_KEYS: [&str; 3] = ["compact", "text", "narrative"];

pub(super) const MAX_COMPACT_BYTES: usize = 4096;

pub(super) const MAX_TEXT_BYTES: usize = 32 * 1024;

pub(super) const MAX_NARRATIVE_BYTES: usize = 32 * 1024;

/// Per-tier confidence metadata stored with a PsychProfile snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsychProfileConfidence {
    /// Confidence for the compact tier.
    pub compact: f32,
    /// Confidence for the text tier.
    pub text: f32,
    /// Confidence for the narrative tier.
    pub narrative: f32,
}

impl PsychProfileConfidence {
    /// Creates per-tier confidence metadata, requiring every score to be
    /// finite and in `[0, 1]`.
    pub fn new(compact: f32, text: f32, narrative: f32) -> Result<Self> {
        let confidence = Self {
            compact,
            text,
            narrative,
        };
        confidence.validate()?;
        Ok(confidence)
    }

    fn validate(self) -> Result<()> {
        validate_confidence(self.compact, "compact confidence must be finite in [0, 1]")?;
        validate_confidence(self.text, "text confidence must be finite in [0, 1]")?;
        validate_confidence(
            self.narrative,
            "narrative confidence must be finite in [0, 1]",
        )?;
        Ok(())
    }
}

/// Stored freshness marker for a PsychProfile snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PsychProfileSnapshotStatus {
    /// Snapshot source revisions still match the caller's source set.
    Fresh,
    /// Snapshot was explicitly marked stale by the profile pipeline.
    Stale,
}

impl PsychProfileSnapshotStatus {
    /// Returns the pinned on-disk integer code for this status.
    #[must_use]
    pub const fn as_code(self) -> u64 {
        match self {
            Self::Fresh => 1,
            Self::Stale => 2,
        }
    }

    pub(super) fn parse_code(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Fresh),
            2 => Some(Self::Stale),
            _ => None,
        }
    }
}

/// Reason a persisted PsychProfile snapshot should not be treated as current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsychProfileStaleReason {
    /// The stored snapshot carries `status = stale`.
    MarkedStale,
    /// The caller supplied a source-revision set that differs from the
    /// canonical set persisted on the snapshot.
    SourceRevisionMismatch {
        /// Canonical source revision ids the caller expected.
        expected: Vec<EntityId>,
        /// Canonical source revision ids stored on the snapshot.
        actual: Vec<EntityId>,
    },
}

/// Typed lookup state for a PsychProfile snapshot.
#[derive(Debug, Clone, PartialEq)]
pub enum PsychProfileState {
    /// No PSYCH_PROFILE entity exists at the requested id.
    Missing,
    /// A profile exists and is current for the supplied source set.
    Fresh(PsychProfile),
    /// A profile exists but is stale for a typed reason.
    Stale {
        /// The persisted profile snapshot.
        profile: PsychProfile,
        /// Why the snapshot is stale.
        reason: PsychProfileStaleReason,
    },
}

/// Persisted PsychProfile snapshot record.
#[derive(Debug, Clone, PartialEq)]
pub struct PsychProfile {
    /// Entity the profile describes.
    pub subject_ref: EntityId,
    /// Compact tier optimized for cheap profile display.
    pub compact: String,
    /// Text tier optimized for retrieval/context assembly.
    pub text: String,
    /// Narrative tier optimized for companion mirror rendering.
    pub narrative: String,
    /// Canonical source revision ids used to build this snapshot.
    pub source_revision_ids: Vec<EntityId>,
    /// Per-tier confidence metadata.
    pub confidence: PsychProfileConfidence,
    /// Stored freshness marker.
    pub status: PsychProfileSnapshotStatus,
}

impl PsychProfile {
    /// Builds a fresh PsychProfile snapshot and canonicalizes source revisions
    /// by sorting and deduplicating them.
    pub fn new(
        subject_ref: EntityId,
        compact: impl Into<String>,
        text: impl Into<String>,
        narrative: impl Into<String>,
        source_revision_ids: Vec<EntityId>,
        confidence: PsychProfileConfidence,
    ) -> Result<Self> {
        let profile = Self {
            subject_ref,
            compact: compact.into(),
            text: text.into(),
            narrative: narrative.into(),
            source_revision_ids: canonical_source_revision_ids(source_revision_ids)?,
            confidence,
            status: PsychProfileSnapshotStatus::Fresh,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Returns this profile with an explicit stored stale marker.
    #[must_use]
    pub fn marked_stale(mut self) -> Self {
        self.status = PsychProfileSnapshotStatus::Stale;
        self
    }

    /// Replaces the stored freshness marker.
    #[must_use]
    pub fn with_status(mut self, status: PsychProfileSnapshotStatus) -> Self {
        self.status = status;
        self
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_text(
            &self.compact,
            MAX_COMPACT_BYTES,
            "compact profile tier must be non-empty and at most 4096 bytes",
        )?;
        validate_text(
            &self.text,
            MAX_TEXT_BYTES,
            "text profile tier must be non-empty and at most 32768 bytes",
        )?;
        validate_text(
            &self.narrative,
            MAX_NARRATIVE_BYTES,
            "narrative profile tier must be non-empty and at most 32768 bytes",
        )?;
        if self.source_revision_ids.is_empty() {
            return Err(invalid_profile(
                "sourceRevisionIds must contain at least one revision id",
            ));
        }
        if !self
            .source_revision_ids
            .windows(2)
            .all(|ids| ids[0] < ids[1])
        {
            return Err(invalid_profile(
                "sourceRevisionIds must be canonical sorted unique ids",
            ));
        }
        self.confidence.validate()?;
        Ok(())
    }
}
