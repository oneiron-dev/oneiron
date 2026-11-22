//! The retrieval pipeline's scoring numbers as one value passed per call
//! (RESEARCH-0651 contract item 1; ARCH-0037 #tune-retrieval-gaps).
//!
//! A [`PipelineBuilder`](super::PipelineBuilder) scores with
//! [`RetrievalParams::shipped`] unless the caller hands it a candidate set
//! through [`PipelineBuilder::retrieval_params`](super::PipelineBuilder::retrieval_params).
//! The set lives for that one call: no verb, setting or stored row holds it,
//! so the next call scores with the shipped numbers again (ARCH-0037: the
//! retrieval skill carries these numbers, and only the skill-improvement loop
//! changes them). The run's fork hash names the set by [`RetrievalParams::digest`]
//! and [`RETRIEVAL_FORMULA_VERSION`], so a candidate run's trace never passes
//! for a shipped one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{
    ALPHA_BASE, ALPHA_RANGE, ALPHA_TAU_SECS, CONTEXT_PACK_ANOMALOUS_REPEAT_RUN,
    CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO, COSINE_GHOST_VECTOR_THRESHOLD, PPR_DAMPING,
    RECENCY_DECAY_TAU_SECS, TEMPORAL_FLOOR, TEMPORAL_WIDENING_FLOOR, TEMPORAL_WIDENING_MULTIPLE,
};
use crate::error::{Error, Result};
use oneiron_store::batch::phonetic_codes::{NPD_CAP, NPD_KEEP_RATIO, NPD_THRESHOLD};

/// The version of the scoring formulas that read [`RetrievalParams`]. A
/// change to how a number is used, rather than to the number, bumps it; the
/// fork hash carries it beside [`RetrievalParams::digest`].
pub const RETRIEVAL_FORMULA_VERSION: u32 = 1;

/// The scoring numbers one retrieval call reads. Every field is a number the
/// pipeline used to read as a compiled-in constant; [`Self::shipped`] holds
/// today's values.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalParams {
    /// The temporal sigmoid's floor: the proximity score of a row far from
    /// the anchor.
    pub temporal_floor: f64,
    /// The decay constant of the temporal channel's recency term,
    /// `exp(-age / tau)`, in seconds.
    pub recency_decay_tau_secs: f64,
    /// The temporal blend's proximity weight for an anchor at now; the
    /// weight grows by up to [`Self::alpha_range`] as the anchor ages.
    pub alpha_base: f64,
    /// How much the proximity weight grows for an old anchor.
    pub alpha_range: f64,
    /// The time constant of that growth, in seconds.
    pub alpha_tau_secs: f64,
    /// Personalized PageRank's teleport probability (the walk's damping).
    pub ppr_damping: f32,
    /// A scoped temporal channel widens to at most this multiple of the rows
    /// it was asked for (ARCH-0004 #temporal-bound).
    pub temporal_widening_multiple: usize,
    /// ... and to at least this many rows.
    pub temporal_widening_floor: usize,
    /// A vector hit above this cosine with no text hit is a cosine ghost,
    /// which the gravity blend dampens.
    pub cosine_ghost_vector_threshold: f32,
    /// RET-01: a vector list whose `(top1 - top2) / top1` is below this
    /// ratio is a poor match, and the context pack may abstain.
    pub context_pack_min_vector_score_gap_ratio: f32,
    /// RET-01: a text query with a run of this many repeated characters is
    /// anomalous, and the context pack abstains.
    pub context_pack_anomalous_repeat_run: usize,
    /// The phonetic channel's sound match (CROSS-ARCH-0013 rung 1): a
    /// stored sound key further than this Normalized Phonetic Distance from
    /// the query's is no match.
    pub phonetic_npd_threshold: f32,
    /// ... of the rest, those within this multiple of the nearest one's
    /// distance are kept ...
    pub phonetic_npd_keep_ratio: f32,
    /// ... nearest first, at most this many.
    pub phonetic_npd_cap: usize,
}

/// The value type of a knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnobKind {
    Float,
    Integer,
}

/// The retrieval stage a knob acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnobAxis {
    /// The temporal channel's scoring and its scoped widening.
    Temporal,
    /// The graph walk (Personalized PageRank).
    Graph,
    /// The blend over the fused lists.
    Blend,
    /// The context pack's RET-01 abstention.
    ContextPack,
    /// The phonetic channel's sound match.
    Phonetic,
}

/// The values [`RetrievalParams::validate`] accepts for one knob. An
/// unbounded side is `f64::MAX`; a value must also be finite.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct KnobRange {
    pub min: f64,
    pub max: f64,
    pub min_inclusive: bool,
    pub max_inclusive: bool,
}

impl KnobRange {
    const fn closed(min: f64, max: f64) -> Self {
        Self {
            min,
            max,
            min_inclusive: true,
            max_inclusive: true,
        }
    }

    const fn positive() -> Self {
        Self {
            min: 0.0,
            max: f64::MAX,
            min_inclusive: false,
            max_inclusive: true,
        }
    }

    /// Whether `value` is finite and inside the range.
    #[must_use]
    pub fn contains(&self, value: f64) -> bool {
        let above_min = if self.min_inclusive {
            value >= self.min
        } else {
            value > self.min
        };
        let below_max = if self.max_inclusive {
            value <= self.max
        } else {
            value < self.max
        };
        value.is_finite() && above_min && below_max
    }
}

/// One knob of [`RetrievalParams`]: its field name, value type, accepted
/// range, the stage it acts on, and whether a change needs an index rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct KnobSpec {
    pub path: &'static str,
    pub kind: KnobKind,
    pub range: KnobRange,
    pub axis: KnobAxis,
    pub requires_rebuild: bool,
}

const fn knob(path: &'static str, kind: KnobKind, range: KnobRange, axis: KnobAxis) -> KnobSpec {
    KnobSpec {
        path,
        kind,
        range,
        axis,
        // Every knob here is read at query time; none is baked into an index.
        requires_rebuild: false,
    }
}

const RETRIEVAL_KNOB_COUNT: usize = 14;

/// In the order of [`RetrievalParams::knob_values`].
static RETRIEVAL_KNOB_SCHEMA: [KnobSpec; RETRIEVAL_KNOB_COUNT] = [
    knob(
        "temporal_floor",
        KnobKind::Float,
        KnobRange {
            min: 0.0,
            max: 1.0,
            min_inclusive: true,
            // The proximity blend divides by `1 - floor`.
            max_inclusive: false,
        },
        KnobAxis::Temporal,
    ),
    knob(
        "recency_decay_tau_secs",
        KnobKind::Float,
        KnobRange::positive(),
        KnobAxis::Temporal,
    ),
    knob(
        "alpha_base",
        KnobKind::Float,
        KnobRange::closed(0.0, 1.0),
        KnobAxis::Temporal,
    ),
    knob(
        "alpha_range",
        KnobKind::Float,
        KnobRange::closed(0.0, 1.0),
        KnobAxis::Temporal,
    ),
    knob(
        "alpha_tau_secs",
        KnobKind::Float,
        KnobRange::positive(),
        KnobAxis::Temporal,
    ),
    knob(
        "ppr_damping",
        KnobKind::Float,
        KnobRange {
            min: 0.0,
            max: 1.0,
            min_inclusive: false,
            max_inclusive: false,
        },
        KnobAxis::Graph,
    ),
    knob(
        "temporal_widening_multiple",
        KnobKind::Integer,
        KnobRange::closed(1.0, f64::MAX),
        KnobAxis::Temporal,
    ),
    knob(
        "temporal_widening_floor",
        KnobKind::Integer,
        KnobRange::closed(0.0, f64::MAX),
        KnobAxis::Temporal,
    ),
    knob(
        "cosine_ghost_vector_threshold",
        KnobKind::Float,
        KnobRange::closed(-1.0, 1.0),
        KnobAxis::Blend,
    ),
    knob(
        "context_pack_min_vector_score_gap_ratio",
        KnobKind::Float,
        KnobRange::closed(0.0, 1.0),
        KnobAxis::ContextPack,
    ),
    knob(
        "context_pack_anomalous_repeat_run",
        KnobKind::Integer,
        // A run of one would make every query anomalous.
        KnobRange::closed(2.0, f64::MAX),
        KnobAxis::ContextPack,
    ),
    knob(
        "phonetic_npd_threshold",
        KnobKind::Float,
        KnobRange::closed(0.0, f64::MAX),
        KnobAxis::Phonetic,
    ),
    knob(
        "phonetic_npd_keep_ratio",
        KnobKind::Float,
        // Below 1 the nearest match itself would be dropped.
        KnobRange::closed(1.0, f64::MAX),
        KnobAxis::Phonetic,
    ),
    knob(
        "phonetic_npd_cap",
        KnobKind::Integer,
        KnobRange::closed(1.0, f64::MAX),
        KnobAxis::Phonetic,
    ),
];

/// Every knob of [`RetrievalParams`], in field order.
#[must_use]
pub fn retrieval_knob_schema() -> &'static [KnobSpec] {
    &RETRIEVAL_KNOB_SCHEMA
}

impl Default for RetrievalParams {
    fn default() -> Self {
        Self::shipped()
    }
}

impl RetrievalParams {
    /// Today's numbers: the ones every call scores with unless it is handed
    /// another set.
    #[must_use]
    pub const fn shipped() -> Self {
        Self {
            temporal_floor: TEMPORAL_FLOOR,
            recency_decay_tau_secs: RECENCY_DECAY_TAU_SECS,
            alpha_base: ALPHA_BASE,
            alpha_range: ALPHA_RANGE,
            alpha_tau_secs: ALPHA_TAU_SECS,
            ppr_damping: PPR_DAMPING,
            temporal_widening_multiple: TEMPORAL_WIDENING_MULTIPLE,
            temporal_widening_floor: TEMPORAL_WIDENING_FLOOR,
            cosine_ghost_vector_threshold: COSINE_GHOST_VECTOR_THRESHOLD,
            context_pack_min_vector_score_gap_ratio: CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO,
            context_pack_anomalous_repeat_run: CONTEXT_PACK_ANOMALOUS_REPEAT_RUN,
            phonetic_npd_threshold: NPD_THRESHOLD,
            phonetic_npd_keep_ratio: NPD_KEEP_RATIO,
            phonetic_npd_cap: NPD_CAP,
        }
    }

    /// The knob values in [`retrieval_knob_schema`] order. The integer knobs
    /// are compared as `f64`; their bounds are far below where that rounds.
    fn knob_values(&self) -> [f64; RETRIEVAL_KNOB_COUNT] {
        [
            self.temporal_floor,
            self.recency_decay_tau_secs,
            self.alpha_base,
            self.alpha_range,
            self.alpha_tau_secs,
            f64::from(self.ppr_damping),
            self.temporal_widening_multiple as f64,
            self.temporal_widening_floor as f64,
            f64::from(self.cosine_ghost_vector_threshold),
            f64::from(self.context_pack_min_vector_score_gap_ratio),
            self.context_pack_anomalous_repeat_run as f64,
            f64::from(self.phonetic_npd_threshold),
            f64::from(self.phonetic_npd_keep_ratio),
            self.phonetic_npd_cap as f64,
        ]
    }

    /// Refuses a set with a knob outside its [`retrieval_knob_schema`] range,
    /// a non-finite number, or a temporal blend whose proximity weight could
    /// pass 1 (`alpha_base + alpha_range > 1`).
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] naming the first knob refused.
    pub fn validate(&self) -> Result<()> {
        for (spec, value) in RETRIEVAL_KNOB_SCHEMA.iter().zip(self.knob_values()) {
            if !spec.range.contains(value) {
                return Err(Error::InvalidConfig(format!(
                    "retrieval param {} = {value} is outside its range {:?}",
                    spec.path, spec.range
                )));
            }
        }
        if self.alpha_base + self.alpha_range > 1.0 {
            return Err(Error::InvalidConfig(format!(
                "retrieval params alpha_base + alpha_range = {} exceeds 1",
                self.alpha_base + self.alpha_range
            )));
        }
        Ok(())
    }

    /// The set's identity: sha256 over its RFC 8785 (JCS) canonical JSON.
    /// Equal sets have equal digests on every host and in every language.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for a set [`Self::validate`] refuses (JSON
    /// has no NaN or infinity to canonicalize).
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let canonical = serde_json_canonicalizer::to_vec(self).map_err(|_| {
            Error::InvariantViolation("retrieval params canonical JSON encode failed")
        })?;
        Ok(Sha256::digest(canonical).into())
    }
}
