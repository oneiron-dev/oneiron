//! Snapshot record types, projections, and constructors/validators.

use super::codec::{
    canonical_source_revision_ids, invalid_profile, validate_confidence, validate_text,
};
use crate::revision_ref::RevisionRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::Result;

/// Current PsychProfile record body schema version. Schema 3: every source
/// carries the exact version and words it was read from (FIX 11766); a row
/// of an earlier schema is known from its envelope and never decoded.
pub const PSYCH_PROFILE_SCHEMA_VERSION: u64 = 3;

/// Domain of [`psych_profile_words_pin`].
pub const PSYCH_PROFILE_WORDS_PIN_DOMAIN: &[u8] = b"oneiron:psych-profile:source-words:v1";

/// Pinned on-disk MessagePack key set for PSYCH_PROFILE bodies. Source
/// revisions and sources are paged codec frames (FIX 10054).
pub const PSYCH_PROFILE_BODY_KEYS: [&str; 9] = [
    "schemaVersion",
    "subjectRef",
    "compact",
    "text",
    "narrative",
    "sourceRevisionPages",
    "confidence",
    "status",
    "sourcePages",
];

/// Minimal projection: enough to answer "is there a profile and is it fresh?"
pub const PSYCH_PROFILE_FIELDS_MINIMAL: &[&str] = &[
    "schemaVersion",
    "subjectRef",
    "sourceRevisionPages",
    "status",
];

/// Standard projection: add the cheap compact render and confidence metadata.
pub const PSYCH_PROFILE_FIELDS_STANDARD: &[&str] = &[
    "schemaVersion",
    "subjectRef",
    "compact",
    "sourceRevisionPages",
    "confidence",
    "status",
];

/// Full projection: every persisted PsychProfile field.
pub const PSYCH_PROFILE_FIELDS_FULL: &[&str] = &PSYCH_PROFILE_BODY_KEYS;

pub const KEY_SCHEMA_VERSION: &str = PSYCH_PROFILE_BODY_KEYS[0];

pub const KEY_SUBJECT_REF: &str = PSYCH_PROFILE_BODY_KEYS[1];

pub const KEY_COMPACT: &str = PSYCH_PROFILE_BODY_KEYS[2];

pub const KEY_TEXT: &str = PSYCH_PROFILE_BODY_KEYS[3];

pub const KEY_NARRATIVE: &str = PSYCH_PROFILE_BODY_KEYS[4];

pub const KEY_SOURCE_REVISION_PAGES: &str = PSYCH_PROFILE_BODY_KEYS[5];

pub const KEY_CONFIDENCE: &str = PSYCH_PROFILE_BODY_KEYS[6];

pub const KEY_STATUS: &str = PSYCH_PROFILE_BODY_KEYS[7];

pub const KEY_SOURCE_PAGES: &str = PSYCH_PROFILE_BODY_KEYS[8];

pub const CONFIDENCE_KEYS: [&str; 3] = ["compact", "text", "narrative"];

pub const MAX_COMPACT_BYTES: usize = 4096;

pub const MAX_TEXT_BYTES: usize = 32 * 1024;

pub const MAX_NARRATIVE_BYTES: usize = 32 * 1024;

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

    pub(crate) fn parse_code(value: u64) -> Option<Self> {
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

/// One half-open byte range `start..end` of a source text (FIX 11766).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PsychProfileByteRange {
    /// First byte of the range.
    pub start: u64,
    /// One past the last byte of the range.
    pub end: u64,
}

/// The text of a source's exact version that a span's byte ranges are
/// measured over (FIX 11766).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsychProfileSpanText {
    /// The record document's text at this incarnation-qualified frontier,
    /// in the form `entity_doc::source_frontier_in_txn` names one.
    Document {
        /// Incarnation-qualified document frontier.
        frontier: Vec<u8>,
    },
    /// The top-level string field `field` of the record body at the
    /// version: a record with no document, so no frontier is recorded.
    Field {
        /// Name of the body field.
        field: String,
    },
}

/// What the words a span selects were pinned as when the profile was
/// built (FIX 11766), each a [`psych_profile_words_pin`] hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsychProfileWordsPin {
    /// The selected words as stored.
    Content([u8; 32]),
    /// The selected words as the producer's read projected them: each
    /// lifted key read as its handle.
    Projection([u8; 32]),
}

/// The exact words of one source version a snapshot was built from (FIX
/// 11766): the whole record, or spans of its text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsychProfileSourceWords {
    /// Record-native: the whole record at the version, pinned by the
    /// `swarm_evidence_content_hash` of the body that version reads as.
    Record {
        /// Content hash of the version's body.
        content: [u8; 32],
    },
    /// Document spans: ascending, non-overlapping, non-empty byte ranges of
    /// `text`, and the pin of the words they select, in range order.
    Spans {
        /// The text the ranges are measured over.
        text: PsychProfileSpanText,
        /// The ranges, at least one.
        ranges: Vec<PsychProfileByteRange>,
        /// The pin of the selected words.
        pin: PsychProfileWordsPin,
    },
}

impl PsychProfileSourceWords {
    fn validate(&self) -> Result<()> {
        let Self::Spans { text, ranges, .. } = self else {
            return Ok(());
        };
        let text_named = match text {
            PsychProfileSpanText::Document { frontier } => !frontier.is_empty(),
            PsychProfileSpanText::Field { field } => !field.is_empty(),
        };
        if !text_named
            || ranges.is_empty()
            || ranges.iter().any(|range| range.start >= range.end)
            || !ranges.windows(2).all(|pair| pair[0].end <= pair[1].start)
        {
            return Err(invalid_profile(
                "source spans must name their text and hold ascending, non-overlapping, \
                 non-empty half-open byte ranges",
            ));
        }
        Ok(())
    }
}

/// The pin of `words`, the words a span's ranges select in range order
/// (FIX 11766): the producer and every reader hash them alike.
#[must_use]
pub fn psych_profile_words_pin<S: AsRef<str>>(words: impl IntoIterator<Item = S>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PSYCH_PROFILE_WORDS_PIN_DOMAIN);
    for word in words {
        let word = word.as_ref();
        hasher.update(&(word.len() as u64).to_be_bytes());
        hasher.update(word.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// One source a snapshot was built from (FIX 8141, 11766): the generation
/// input it belongs to, the record whose words that input carried, the
/// exact version of that record read, the words of it the profile was
/// built from, and the WORLD the record lies in. A recipient read honours
/// the owner's recipient choice for every source's world, as for the world
/// the read names, and a reader's own credential is judged on the exact
/// words.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PsychProfileSource {
    /// The generation input, one of the snapshot's source revision ids.
    pub revision_ref: EntityId,
    /// The record whose words the input carried.
    pub document_ref: EntityId,
    /// The WORLD the record lies in; None for a world-free record.
    pub world_ref: Option<EntityId>,
    /// The exact stored revision of `document_ref` read.
    pub document_revision: RevisionRef,
    /// The words of that revision the profile was built from.
    pub words: PsychProfileSourceWords,
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
    /// The exact words behind each source and where it lives, canonical;
    /// each cites one of `source_revision_ids`. A stored snapshot holds at
    /// least one for every source revision id (FIX 11766).
    pub sources: Vec<PsychProfileSource>,
}

impl PsychProfile {
    /// Builds a fresh PsychProfile snapshot and canonicalizes source revisions
    /// by sorting and deduplicating them. It has no sources yet: it is
    /// stored only once [`Self::with_sources`] gives every source revision
    /// the exact words it was read from (FIX 11766).
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
            sources: Vec::new(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// This snapshot with its sources (FIX 8141, 11766), canonicalized by
    /// sorting and deduplicating them. Each must cite one of the snapshot's
    /// own source revisions.
    pub fn with_sources(mut self, mut sources: Vec<PsychProfileSource>) -> Result<Self> {
        sources.sort_unstable();
        sources.dedup();
        self.sources = sources;
        self.validate()?;
        Ok(self)
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

    pub(crate) fn validate(&self) -> Result<()> {
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
        if !self.sources.windows(2).all(|pair| pair[0] < pair[1])
            || self.sources.iter().any(|source| {
                self.source_revision_ids
                    .binary_search(&source.revision_ref)
                    .is_err()
            })
        {
            return Err(invalid_profile(
                "sources must be canonical and cite the snapshot's own source revisions",
            ));
        }
        for source in &self.sources {
            source.words.validate()?;
        }
        self.confidence.validate()?;
        Ok(())
    }

    /// Refuses a snapshot any of whose source revisions (its generation
    /// inputs) has no source carrying the exact words it was read from
    /// (FIX 11766). Every stored snapshot meets it.
    pub fn validate_source_words(&self) -> Result<()> {
        let covered = |revision: &EntityId| {
            let at = self
                .sources
                .partition_point(|source| source.revision_ref < *revision);
            self.sources
                .get(at)
                .is_some_and(|source| source.revision_ref == *revision)
        };
        if self.source_revision_ids.iter().all(covered) {
            Ok(())
        } else {
            Err(invalid_profile(
                "every source revision needs a source carrying the exact words it was read from",
            ))
        }
    }
}
