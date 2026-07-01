//! PsychProfile snapshot record substrate.
//!
//! PsychProfile rows are derived, engine-authored snapshots over profile and
//! affect Claims. The record stores three render tiers plus deterministic
//! source-revision tracking so callers can distinguish a missing profile from
//! a stale one without stringly sentinel states.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::unit_interval_f32;
use crate::error::{Error, Result};

use super::{ENTITY_TYPE_PSYCH_PROFILE, EntityId, TimeRange};

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

const KEY_SCHEMA_VERSION: &str = PSYCH_PROFILE_BODY_KEYS[0];
const KEY_SUBJECT_REF: &str = PSYCH_PROFILE_BODY_KEYS[1];
const KEY_COMPACT: &str = PSYCH_PROFILE_BODY_KEYS[2];
const KEY_TEXT: &str = PSYCH_PROFILE_BODY_KEYS[3];
const KEY_NARRATIVE: &str = PSYCH_PROFILE_BODY_KEYS[4];
const KEY_SOURCE_REVISION_IDS: &str = PSYCH_PROFILE_BODY_KEYS[5];
const KEY_CONFIDENCE: &str = PSYCH_PROFILE_BODY_KEYS[6];
const KEY_STATUS: &str = PSYCH_PROFILE_BODY_KEYS[7];

const CONFIDENCE_KEYS: [&str; 3] = ["compact", "text", "narrative"];
const MAX_COMPACT_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 32 * 1024;
const MAX_NARRATIVE_BYTES: usize = 32 * 1024;
const PSYCH_MIRROR_RECENCY_HALF_LIFE_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0;

/// Default source-selection weights for Psych Mirror snapshots.
///
/// Connectivity leads, affect/salience follows, and recency/entropy are
/// smaller tiebreaking signals. The scorer normalizes custom weights by their
/// sum so totals remain comparable.
pub const PSYCH_MIRROR_SELECTION_WEIGHTS: PsychMirrorSelectionWeights =
    PsychMirrorSelectionWeights {
        connectivity: 0.40,
        affect_salience: 0.25,
        recency: 0.20,
        entropy: 0.15,
    };

/// Relative weights applied to Psych Mirror source-selection signals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsychMirrorSelectionWeights {
    pub connectivity: f32,
    pub affect_salience: f32,
    pub recency: f32,
    pub entropy: f32,
}

impl PsychMirrorSelectionWeights {
    fn total(self) -> Result<f32> {
        let total = self.connectivity + self.affect_salience + self.recency + self.entropy;
        if self.connectivity.is_finite()
            && self.affect_salience.is_finite()
            && self.recency.is_finite()
            && self.entropy.is_finite()
            && self.connectivity >= 0.0
            && self.affect_salience >= 0.0
            && self.recency >= 0.0
            && self.entropy >= 0.0
            && total.is_finite()
            && total > 0.0
        {
            Ok(total)
        } else {
            Err(invalid_profile(
                "Psych Mirror selection weights must be finite non-negative values with positive sum",
            ))
        }
    }
}

impl Default for PsychMirrorSelectionWeights {
    fn default() -> Self {
        PSYCH_MIRROR_SELECTION_WEIGHTS
    }
}

/// One candidate memory source available to Psych Mirror snapshot generation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsychMirrorSourceCandidate {
    pub source_id: EntityId,
    pub source_revision_ref: EntityId,
    pub connectivity: f32,
    pub affect_salience: f32,
    pub learned_at: u64,
    pub entropy: f32,
}

impl PsychMirrorSourceCandidate {
    /// Creates a selector candidate, normalizing finite non-negative signals
    /// into `[0, 1]` so callers can pass raw retrieval/PPR scores safely.
    pub fn new(
        source_id: EntityId,
        source_revision_ref: EntityId,
        connectivity: f32,
        affect_salience: f32,
        learned_at: u64,
        entropy: f32,
    ) -> Result<Self> {
        Ok(Self {
            source_id,
            source_revision_ref,
            connectivity: normalized_selection_signal(
                connectivity,
                "Psych Mirror connectivity must be finite and non-negative",
            )?,
            affect_salience: normalized_selection_signal(
                affect_salience,
                "Psych Mirror affect/salience must be finite and non-negative",
            )?,
            learned_at,
            entropy: normalized_selection_signal(
                entropy,
                "Psych Mirror entropy must be finite and non-negative",
            )?,
        })
    }
}

/// Weighted score contributions for a selected Psych Mirror source.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsychMirrorSelectionScore {
    pub connectivity: f32,
    pub affect_salience: f32,
    pub recency: f32,
    pub entropy: f32,
    pub total: f32,
}

/// Ranked source selected for Psych Mirror snapshot generation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsychMirrorSelectedSource {
    pub rank: usize,
    pub source_id: EntityId,
    pub source_revision_ref: EntityId,
    pub score: PsychMirrorSelectionScore,
}

/// Drift-anchor state emitted when comparing old and new Psych Mirror sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PsychMirrorDriftAnchorState {
    /// Existing snapshot source revision remains selected.
    Keep,
    /// Existing snapshot source revision fell out of selection and should be
    /// available for revert decisions.
    Revert,
    /// Newly selected source revision should tune the next snapshot.
    Tune,
}

impl PsychMirrorDriftAnchorState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Revert => "revert",
            Self::Tune => "tune",
        }
    }
}

/// Stable drift-anchor bookkeeping state for one source revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PsychMirrorDriftAnchor {
    pub state: PsychMirrorDriftAnchorState,
    pub source_revision_ref: EntityId,
}

impl PsychMirrorDriftAnchor {
    #[must_use]
    pub const fn event(self) -> PsychMirrorDriftAnchorEvent {
        PsychMirrorDriftAnchorEvent {
            state: self.state,
            source_revision_ref: self.source_revision_ref,
        }
    }
}

/// Event emitted from drift-anchor bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PsychMirrorDriftAnchorEvent {
    pub state: PsychMirrorDriftAnchorState,
    pub source_revision_ref: EntityId,
}

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

    fn parse_code(value: u64) -> Option<Self> {
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

    fn validate(&self) -> Result<()> {
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

/// Ranks Psych Mirror source candidates with the default deterministic weights.
pub fn rank_psych_mirror_sources(
    candidates: &[PsychMirrorSourceCandidate],
    now_secs: u64,
    limit: usize,
) -> Result<Vec<PsychMirrorSelectedSource>> {
    rank_psych_mirror_sources_with_weights(
        candidates,
        now_secs,
        limit,
        PSYCH_MIRROR_SELECTION_WEIGHTS,
    )
}

/// Ranks Psych Mirror source candidates using caller-supplied weights.
pub fn rank_psych_mirror_sources_with_weights(
    candidates: &[PsychMirrorSourceCandidate],
    now_secs: u64,
    limit: usize,
    weights: PsychMirrorSelectionWeights,
) -> Result<Vec<PsychMirrorSelectedSource>> {
    let mut ranked = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let score = psych_mirror_selection_score(candidate, now_secs, weights)?;
        ranked.push(PsychMirrorSelectedSource {
            rank: 0,
            source_id: candidate.source_id,
            source_revision_ref: candidate.source_revision_ref,
            score,
        });
    }

    ranked.sort_unstable_by(|left, right| {
        right
            .score
            .total
            .total_cmp(&left.score.total)
            .then_with(|| {
                left.source_revision_ref
                    .as_bytes()
                    .cmp(right.source_revision_ref.as_bytes())
            })
            .then_with(|| left.source_id.as_bytes().cmp(right.source_id.as_bytes()))
    });
    ranked.truncate(limit);
    for (index, source) in ranked.iter_mut().enumerate() {
        source.rank = index + 1;
    }
    Ok(ranked)
}

fn psych_mirror_selection_score(
    candidate: &PsychMirrorSourceCandidate,
    now_secs: u64,
    weights: PsychMirrorSelectionWeights,
) -> Result<PsychMirrorSelectionScore> {
    let weight_total = weights.total()?;
    let connectivity = normalized_selection_signal(
        candidate.connectivity,
        "Psych Mirror connectivity must be finite and non-negative",
    )? * weights.connectivity
        / weight_total;
    let affect_salience = normalized_selection_signal(
        candidate.affect_salience,
        "Psych Mirror affect/salience must be finite and non-negative",
    )? * weights.affect_salience
        / weight_total;
    let recency =
        psych_mirror_recency_score(candidate.learned_at, now_secs) * weights.recency / weight_total;
    let entropy = normalized_selection_signal(
        candidate.entropy,
        "Psych Mirror entropy must be finite and non-negative",
    )? * weights.entropy
        / weight_total;
    Ok(PsychMirrorSelectionScore {
        connectivity,
        affect_salience,
        recency,
        entropy,
        total: connectivity + affect_salience + recency + entropy,
    })
}

fn psych_mirror_recency_score(learned_at: u64, now_secs: u64) -> f32 {
    let age_secs = now_secs.saturating_sub(learned_at) as f64;
    2.0_f64.powf(-age_secs / PSYCH_MIRROR_RECENCY_HALF_LIFE_SECS) as f32
}

fn normalized_selection_signal(value: f32, context: &'static str) -> Result<f32> {
    if value.is_finite() && value >= 0.0 {
        Ok(value.min(1.0))
    } else {
        Err(invalid_profile(context))
    }
}

/// Returns normalized Shannon entropy for a text source in `[0, 1]`.
#[must_use]
pub fn psych_mirror_text_entropy(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }

    let mut counts = [0_u32; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }

    let len = text.len() as f64;
    let mut entropy = 0.0_f64;
    let mut distinct = 0_u32;
    for count in counts.into_iter().filter(|count| *count > 0) {
        distinct += 1;
        let probability = f64::from(count) / len;
        entropy -= probability * probability.log2();
    }

    if distinct <= 1 {
        0.0
    } else {
        (entropy / f64::from(distinct).log2()).clamp(0.0, 1.0) as f32
    }
}

/// Builds deterministic drift anchors from previous and currently selected
/// source revision refs.
#[must_use]
pub fn psych_mirror_drift_anchors(
    previous_source_revision_refs: &[EntityId],
    selected_source_revision_refs: &[EntityId],
) -> Vec<PsychMirrorDriftAnchor> {
    let previous = canonical_revision_refs_allow_empty(previous_source_revision_refs);
    let selected_set: BTreeSet<EntityId> = selected_source_revision_refs.iter().copied().collect();
    let previous_set: BTreeSet<EntityId> = previous.iter().copied().collect();

    let mut anchors = Vec::with_capacity(previous.len() + selected_source_revision_refs.len());
    for source_revision_ref in previous {
        let state = if selected_set.contains(&source_revision_ref) {
            PsychMirrorDriftAnchorState::Keep
        } else {
            PsychMirrorDriftAnchorState::Revert
        };
        anchors.push(PsychMirrorDriftAnchor {
            state,
            source_revision_ref,
        });
    }
    for source_revision_ref in selected_source_revision_refs.iter().copied() {
        if !previous_set.contains(&source_revision_ref) {
            anchors.push(PsychMirrorDriftAnchor {
                state: PsychMirrorDriftAnchorState::Tune,
                source_revision_ref,
            });
        }
    }
    anchors
}

/// Emits typed drift-anchor events for keep/revert/tune source revision refs.
#[must_use]
pub fn psych_mirror_drift_anchor_events(
    previous_source_revision_refs: &[EntityId],
    selected_source_revision_refs: &[EntityId],
) -> Vec<PsychMirrorDriftAnchorEvent> {
    psych_mirror_drift_anchors(previous_source_revision_refs, selected_source_revision_refs)
        .into_iter()
        .map(PsychMirrorDriftAnchor::event)
        .collect()
}

/// Encodes a PsychProfile body in canonical MessagePack field order.
pub fn encode_psych_profile_body(profile: &PsychProfile) -> Result<Vec<u8>> {
    profile.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SUBJECT_REF),
            Value::from(profile.subject_ref.to_hex()),
        ),
        (
            Value::from(KEY_COMPACT),
            Value::from(profile.compact.as_str()),
        ),
        (Value::from(KEY_TEXT), Value::from(profile.text.as_str())),
        (
            Value::from(KEY_NARRATIVE),
            Value::from(profile.narrative.as_str()),
        ),
        (
            Value::from(KEY_SOURCE_REVISION_IDS),
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (
            Value::from(KEY_CONFIDENCE),
            encode_confidence(profile.confidence),
        ),
        (
            Value::from(KEY_STATUS),
            Value::from(profile.status.as_code()),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("psych profile body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a PsychProfile body.
pub fn decode_psych_profile_body(bytes: &[u8]) -> Result<PsychProfile> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_profile("body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_profile("trailing bytes after body map"));
    }
    decode_psych_profile_value(&value)
}

pub(crate) fn validate_psych_profile_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_psych_profile_body(bytes).map(|_| ())
}

fn decode_psych_profile_value(value: &Value) -> Result<PsychProfile> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("body must be a MessagePack map"));
    };
    validate_keys(entries, &PSYCH_PROFILE_BODY_KEYS)?;

    let profile = PsychProfile {
        subject_ref: decode_entity_ref(required_value(entries, KEY_SUBJECT_REF)?)?,
        compact: decode_text_field(
            required_value(entries, KEY_COMPACT)?,
            MAX_COMPACT_BYTES,
            "compact profile tier must be non-empty and at most 4096 bytes",
        )?,
        text: decode_text_field(
            required_value(entries, KEY_TEXT)?,
            MAX_TEXT_BYTES,
            "text profile tier must be non-empty and at most 32768 bytes",
        )?,
        narrative: decode_text_field(
            required_value(entries, KEY_NARRATIVE)?,
            MAX_NARRATIVE_BYTES,
            "narrative profile tier must be non-empty and at most 32768 bytes",
        )?,
        source_revision_ids: decode_source_revision_ids(required_value(
            entries,
            KEY_SOURCE_REVISION_IDS,
        )?)?,
        confidence: decode_confidence(required_value(entries, KEY_CONFIDENCE)?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_u64()
            .and_then(PsychProfileSnapshotStatus::parse_code)
            .ok_or_else(|| invalid_profile("status must be typed code 1 or 2"))?,
    };

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(PSYCH_PROFILE_SCHEMA_VERSION) {
        return Err(invalid_profile("unsupported schemaVersion"));
    }

    profile.validate()?;
    Ok(profile)
}

fn encode_source_revision_ids(ids: &[EntityId]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| Value::from(id.to_hex()))
            .collect::<Vec<_>>(),
    )
}

fn decode_source_revision_ids(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(values) = value else {
        return Err(invalid_profile("sourceRevisionIds must be an array"));
    };
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        ids.push(decode_entity_ref(value)?);
    }
    if ids.is_empty() {
        return Err(invalid_profile(
            "sourceRevisionIds must contain at least one revision id",
        ));
    }
    if !ids.windows(2).all(|ids| ids[0] < ids[1]) {
        return Err(invalid_profile(
            "sourceRevisionIds must be canonical sorted unique ids",
        ));
    }
    Ok(ids)
}

fn canonical_source_revision_ids(mut ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(invalid_profile(
            "sourceRevisionIds must contain at least one revision id",
        ));
    }
    Ok(ids)
}

fn canonical_revision_refs_allow_empty(ids: &[EntityId]) -> Vec<EntityId> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn canonical_expected_source_revision_ids(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn encode_confidence(confidence: PsychProfileConfidence) -> Value {
    Value::Map(vec![
        (
            Value::from(CONFIDENCE_KEYS[0]),
            Value::F32(confidence.compact),
        ),
        (Value::from(CONFIDENCE_KEYS[1]), Value::F32(confidence.text)),
        (
            Value::from(CONFIDENCE_KEYS[2]),
            Value::F32(confidence.narrative),
        ),
    ])
}

fn decode_confidence(value: &Value) -> Result<PsychProfileConfidence> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("confidence must be a MessagePack map"));
    };
    validate_keys(entries, &CONFIDENCE_KEYS)?;
    PsychProfileConfidence::new(
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[0])?, "compact")?,
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[1])?, "text")?,
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[2])?, "narrative")?,
    )
}

fn decode_confidence_value(value: &Value, field: &'static str) -> Result<f32> {
    let Some(score) = unit_interval_f32(value) else {
        return Err(match field {
            "compact" => invalid_profile("compact confidence must be finite in [0, 1]"),
            "text" => invalid_profile("text confidence must be finite in [0, 1]"),
            "narrative" => invalid_profile("narrative confidence must be finite in [0, 1]"),
            _ => invalid_profile("confidence must be finite in [0, 1]"),
        });
    };
    Ok(score)
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid_profile("entity refs must be hex strings"))?;
    EntityId::from_hex(hex).map_err(|_| invalid_profile("entity refs must be valid entity ids"))
}

fn decode_text_field(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid_profile("profile tier must be a UTF-8 string"))?;
    validate_text(text, max_bytes, context)?;
    Ok(text.to_owned())
}

fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(invalid_profile(context));
    }
    Ok(())
}

fn validate_confidence(value: f32, context: &'static str) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(invalid_profile(context))
    }
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| invalid_profile("body keys must be strings"))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_profile(
                "body key is not in the pinned PSYCH_PROFILE_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_profile("duplicate body key"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_profile("missing required profile field"))
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_profile("missing required profile field"))
}

fn invalid_profile(reason: &'static str) -> Error {
    Error::InvalidPsychProfileBody(reason)
}

impl crate::Vault {
    /// Stores an engine-authored PsychProfile snapshot record.
    ///
    /// Generic public puts of `ENTITY_TYPE_PSYCH_PROFILE` remain rejected as a
    /// maintenance kind; this helper validates the pinned body schema before
    /// using the internal maintenance write path.
    pub fn put_psych_profile(&self, id: &EntityId, profile: &PsychProfile) -> Result<()> {
        let data = encode_psych_profile_body(profile)?;
        let learned_at = crate::unix_seconds_now();
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_PSYCH_PROFILE,
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

    /// Reads and decodes a PsychProfile snapshot record.
    pub fn get_psych_profile(&self, id: &EntityId) -> Result<Option<PsychProfile>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_PSYCH_PROFILE {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_psych_profile_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Returns a typed missing/fresh/stale state for a PsychProfile snapshot.
    ///
    /// `expected_source_revision_ids = None` checks only the stored stale
    /// marker. Supplying a source set also compares against the persisted
    /// canonical sourceRevisionIds.
    pub fn psych_profile_state(
        &self,
        id: &EntityId,
        expected_source_revision_ids: Option<&[EntityId]>,
    ) -> Result<PsychProfileState> {
        let Some(profile) = self.get_psych_profile(id)? else {
            return Ok(PsychProfileState::Missing);
        };
        if profile.status == PsychProfileSnapshotStatus::Stale {
            return Ok(PsychProfileState::Stale {
                profile,
                reason: PsychProfileStaleReason::MarkedStale,
            });
        }
        if let Some(expected) = expected_source_revision_ids {
            let expected = canonical_expected_source_revision_ids(expected.to_vec());
            if expected != profile.source_revision_ids {
                let actual = profile.source_revision_ids.clone();
                return Ok(PsychProfileState::Stale {
                    profile,
                    reason: PsychProfileStaleReason::SourceRevisionMismatch { expected, actual },
                });
            }
        }
        Ok(PsychProfileState::Fresh(profile))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rmpv::Value;

    use super::*;
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::context_pack::{
        psych_mirror_source_candidate_from_claim, psych_mirror_source_candidate_from_context_entity,
    };
    use crate::types::ContextEntity;
    use crate::types::{ENTITY_TYPE_PERSON, VaultConfig};
    use crate::{ErrorKind, Vault};

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("valid test entity id")
    }

    fn test_profile() -> PsychProfile {
        PsychProfile::new(
            entity(0xA1),
            "fast compact profile",
            "retrieval-friendly profile text",
            "A warm narrative profile.",
            vec![entity(0xC3), entity(0xC1), entity(0xC3), entity(0xC2)],
            PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("valid confidence"),
        )
        .expect("valid profile")
    }

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn msgpack_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(
            &mut out,
            &Value::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (Value::from(key), value))
                    .collect(),
            ),
        )
        .expect("encode msgpack");
        out
    }

    fn fixture_claim(text: &'static str, salience: f32) -> ClaimBody {
        let mut body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(entity(0xA1)),
            Value::from(text),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.salience = Some(salience);
        body
    }

    #[test]
    fn psych_mirror_selection_ranks_fixture_memories_deterministically() -> Result<()> {
        let now = 20_000_000_u64;
        let candidates = vec![
            psych_mirror_source_candidate_from_claim(
                entity(0x11),
                entity(0xB1),
                0.98,
                now - 90 * 86_400,
                &fixture_claim("long-term preference for direct concise answers", 0.10),
            )?,
            psych_mirror_source_candidate_from_claim(
                entity(0x12),
                entity(0xB2),
                0.72,
                now - 2 * 86_400,
                &fixture_claim("high salience self story about anxious onboarding", 0.95),
            )?,
            psych_mirror_source_candidate_from_claim(
                entity(0x13),
                entity(0xB3),
                0.50,
                now,
                &fixture_claim("fresh mixed topic with several distinct cues", 0.55),
            )?,
            psych_mirror_source_candidate_from_claim(
                entity(0x14),
                entity(0xB4),
                0.40,
                now - 30 * 86_400,
                &fixture_claim("abcdefghi jklmnop qrstuv wxyz", 0.20),
            )?,
        ];

        let ranked = rank_psych_mirror_sources(&candidates, now, candidates.len())?;

        assert_eq!(
            ranked
                .iter()
                .map(|source| source.source_revision_ref)
                .collect::<Vec<_>>(),
            vec![entity(0xB2), entity(0xB3), entity(0xB1), entity(0xB4)]
        );
        assert_eq!(
            ranked.iter().map(|source| source.rank).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert!(ranked[0].score.affect_salience > ranked[0].score.connectivity * 0.5);
        assert!(ranked[1].score.recency > ranked[2].score.recency);
        assert!(ranked[3].score.entropy > 0.0);
        Ok(())
    }

    #[test]
    fn psych_mirror_selection_context_entity_adapter_reads_projected_fields() -> Result<()> {
        let mut fields = HashMap::new();
        fields.insert("sal".to_owned(), serde_json::json!(0.7));
        fields.insert("txt".to_owned(), serde_json::json!("distinct context text"));
        let context_entity = ContextEntity {
            id: entity(0x21),
            short_id: "ctx".to_owned(),
            content_hash: 7,
            entity_type: ENTITY_TYPE_PERSON,
            score: 2.0,
            fields: Some(fields),
            edges: None,
            vector: None,
        };

        let candidate =
            psych_mirror_source_candidate_from_context_entity(&context_entity, entity(0xC1), 42)?;

        assert_eq!(candidate.source_revision_ref, entity(0xC1));
        assert_eq!(candidate.connectivity, 1.0);
        assert!((candidate.affect_salience - 0.7).abs() < 1e-6);
        assert!(candidate.entropy > 0.0);

        let mut invalid_salience_fields = HashMap::new();
        invalid_salience_fields.insert("sal".to_owned(), serde_json::json!(1.7));
        invalid_salience_fields
            .insert("txt".to_owned(), serde_json::json!("distinct context text"));
        let invalid_salience_entity = ContextEntity {
            id: entity(0x22),
            short_id: "ctx2".to_owned(),
            content_hash: 8,
            entity_type: ENTITY_TYPE_PERSON,
            score: 0.5,
            fields: Some(invalid_salience_fields),
            edges: None,
            vector: None,
        };
        let invalid_salience_candidate = psych_mirror_source_candidate_from_context_entity(
            &invalid_salience_entity,
            entity(0xC2),
            42,
        )?;

        assert_eq!(invalid_salience_candidate.affect_salience, 0.0);
        Ok(())
    }

    #[test]
    fn psych_mirror_selection_structured_claim_value_contributes_entropy() -> Result<()> {
        let body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(entity(0xA1)),
            Value::Map(vec![
                (
                    Value::from("summary"),
                    Value::from("prefers direct repair notes"),
                ),
                (
                    Value::from("details"),
                    Value::Array(vec![
                        Value::from("tracks source changes carefully"),
                        Value::from(3),
                        Value::Map(vec![(
                            Value::from("nested"),
                            Value::from("asks for concise review replies"),
                        )]),
                    ]),
                ),
            ]),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );

        let candidate =
            psych_mirror_source_candidate_from_claim(entity(0x23), entity(0xC3), 0.5, 42, &body)?;

        assert!(candidate.entropy > 0.0);
        Ok(())
    }

    #[test]
    fn psych_mirror_selection_emits_drift_anchor_events_with_revision_refs() {
        let events = psych_mirror_drift_anchor_events(
            &[entity(0xC3), entity(0xC1), entity(0xC2), entity(0xC2)],
            &[entity(0xC4), entity(0xC1), entity(0xC3), entity(0xC4)],
        );

        assert_eq!(
            events,
            vec![
                PsychMirrorDriftAnchorEvent {
                    state: PsychMirrorDriftAnchorState::Keep,
                    source_revision_ref: entity(0xC1),
                },
                PsychMirrorDriftAnchorEvent {
                    state: PsychMirrorDriftAnchorState::Revert,
                    source_revision_ref: entity(0xC2),
                },
                PsychMirrorDriftAnchorEvent {
                    state: PsychMirrorDriftAnchorState::Keep,
                    source_revision_ref: entity(0xC3),
                },
                PsychMirrorDriftAnchorEvent {
                    state: PsychMirrorDriftAnchorState::Tune,
                    source_revision_ref: entity(0xC4),
                },
                PsychMirrorDriftAnchorEvent {
                    state: PsychMirrorDriftAnchorState::Tune,
                    source_revision_ref: entity(0xC4),
                },
            ]
        );
        assert_eq!(events[0].state.as_str(), "keep");
        assert_eq!(events[1].state.as_str(), "revert");
        assert_eq!(events[3].state.as_str(), "tune");
    }

    #[test]
    fn psych_profile_roundtrip_canonicalizes_source_revisions() -> Result<()> {
        let profile = test_profile();
        assert_eq!(
            profile.source_revision_ids,
            vec![entity(0xC1), entity(0xC2), entity(0xC3)]
        );

        let encoded = encode_psych_profile_body(&profile)?;
        let decoded = decode_psych_profile_body(&encoded)?;

        assert_eq!(decoded, profile);
        Ok(())
    }

    #[test]
    fn psych_profile_rejects_invalid_confidence_and_missing_sources() {
        assert_eq!(
            PsychProfileConfidence::new(1.1, 0.5, 0.5)
                .expect_err("confidence outside unit interval")
                .kind(),
            ErrorKind::InvalidPsychProfileBody
        );
        assert_eq!(
            PsychProfile::new(
                entity(0xA1),
                "compact",
                "text",
                "narrative",
                vec![],
                PsychProfileConfidence::new(0.5, 0.5, 0.5).expect("valid confidence"),
            )
            .expect_err("missing source revisions")
            .kind(),
            ErrorKind::InvalidPsychProfileBody
        );
    }

    #[test]
    fn psych_profile_decoder_rejects_unknown_keys() {
        let profile = test_profile();
        let mut entries = vec![
            (
                KEY_SCHEMA_VERSION,
                Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
            ),
            (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
            (KEY_COMPACT, Value::from(profile.compact.as_str())),
            (KEY_TEXT, Value::from(profile.text.as_str())),
            (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
            (
                KEY_SOURCE_REVISION_IDS,
                encode_source_revision_ids(&profile.source_revision_ids),
            ),
            (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
            (KEY_STATUS, Value::from(profile.status.as_code())),
        ];
        entries.push(("unexpected", Value::from(true)));

        let err = decode_psych_profile_body(&msgpack_map(entries))
            .expect_err("unknown psych profile keys fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
    }

    #[test]
    fn psych_profile_decoder_rejects_noncanonical_source_revisions() {
        let profile = test_profile();
        let entries = vec![
            (
                KEY_SCHEMA_VERSION,
                Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
            ),
            (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
            (KEY_COMPACT, Value::from(profile.compact.as_str())),
            (KEY_TEXT, Value::from(profile.text.as_str())),
            (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
            (
                KEY_SOURCE_REVISION_IDS,
                Value::Array(vec![
                    Value::from(entity(0xC2).to_hex()),
                    Value::from(entity(0xC1).to_hex()),
                ]),
            ),
            (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
            (KEY_STATUS, Value::from(profile.status.as_code())),
        ];

        let err = decode_psych_profile_body(&msgpack_map(entries))
            .expect_err("stored source revisions must be canonical");
        assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
    }

    #[test]
    fn psych_profile_status_persists_as_typed_code_and_rejects_strings() -> Result<()> {
        let profile = test_profile();
        let encoded = encode_psych_profile_body(&profile)?;
        let Value::Map(entries) = rmpv::decode::read_value(&mut Cursor::new(&encoded))
            .expect("encoded profile is MessagePack")
        else {
            panic!("encoded profile must be a MessagePack map");
        };
        assert_eq!(
            required_value(&entries, KEY_STATUS)?.as_u64(),
            Some(profile.status.as_code())
        );

        let string_status_body = msgpack_map(vec![
            (
                KEY_SCHEMA_VERSION,
                Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
            ),
            (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
            (KEY_COMPACT, Value::from(profile.compact.as_str())),
            (KEY_TEXT, Value::from(profile.text.as_str())),
            (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
            (
                KEY_SOURCE_REVISION_IDS,
                encode_source_revision_ids(&profile.source_revision_ids),
            ),
            (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
            (KEY_STATUS, Value::from("fresh")),
        ]);

        let err = decode_psych_profile_body(&string_status_body)
            .expect_err("string status must fail closed under v6 schema");
        assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
        Ok(())
    }

    #[test]
    fn psych_profile_vault_helpers_persist_and_type_lookup_state() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity(0xD1);
        let profile = test_profile();

        assert_eq!(
            vault.psych_profile_state(&id, None)?,
            PsychProfileState::Missing
        );
        vault.put_psych_profile(&id, &profile)?;

        assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_PSYCH_PROFILE));
        assert_eq!(vault.get_psych_profile(&id)?, Some(profile.clone()));
        assert_eq!(
            vault.psych_profile_state(&id, Some(&profile.source_revision_ids))?,
            PsychProfileState::Fresh(profile.clone())
        );

        let stale = vault.psych_profile_state(&id, Some(&[entity(0xC1)]))?;
        assert!(matches!(
            stale,
            PsychProfileState::Stale {
                reason: PsychProfileStaleReason::SourceRevisionMismatch { .. },
                ..
            }
        ));

        let empty_expected = vault.psych_profile_state(&id, Some(&[]))?;
        match empty_expected {
            PsychProfileState::Stale {
                reason: PsychProfileStaleReason::SourceRevisionMismatch { expected, actual },
                ..
            } => {
                assert!(expected.is_empty());
                assert_eq!(actual, profile.source_revision_ids);
            }
            other => {
                panic!("empty expected source set should produce typed stale state: {other:?}")
            }
        }
        Ok(())
    }

    #[test]
    fn psych_profile_public_put_rejects_maintenance_type() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity(0xD1);
        let profile = test_profile();
        let data = encode_psych_profile_body(&profile)?;
        let err = vault
            .put_entity(
                &id,
                ENTITY_TYPE_PSYCH_PROFILE,
                TimeRange { start: 1, end: 1 },
                2,
                &data,
            )
            .expect_err("public generic puts cannot write PsychProfile records");
        assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    #[test]
    fn psych_profile_read_rejects_wrong_entity_type() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity(0xD1);
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            2,
            b"person",
        )?;
        assert_eq!(
            vault
                .get_psych_profile(&id)
                .expect_err("wrong entity type")
                .kind(),
            ErrorKind::InvalidEntityType
        );
        Ok(())
    }
}
