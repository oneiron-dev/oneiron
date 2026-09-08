//! Psych Mirror source selection scoring, entropy, and drift anchors.

use std::collections::BTreeSet;

use super::codec::{canonical_revision_refs_allow_empty, invalid_profile};
use crate::entity_id::EntityId;
use crate::error::Result;

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

const PSYCH_MIRROR_RECENCY_HALF_LIFE_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0;

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
