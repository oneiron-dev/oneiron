//! Moved from `crates/oneiron/src/llm/decision/questions/route_calibration/report.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::ProviderPin;
use oneiron_store::model_decision::questions::DecisionRoute;
use oneiron_store::model_decision::questions::RoutingPolicy;
use serde::Deserialize;
use serde::Serialize;

/// What a route group's pairs share: the question version they were read at, how they were
/// returned, the routing policy revision their receipts pin and the pins whose measurements
/// their probabilities are. A pin's model and version name its backend; a receipt names no
/// other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteGroupKey {
    pub question_version: u32,
    pub route: DecisionRoute,
    pub policy: Option<RoutingPolicy>,
    pub providers: Vec<ProviderPin>,
}

/// One calibration pair by name: the answer and the outcome fact that labelled it (a person's
/// changed answer and a silent window name one row as both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPairRef {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub answer: EntityId,
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub fact: EntityId,
}

/// One knot of a fitted map: a raw probability beside the probability the map fits it to.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MapKnot {
    pub raw: f64,
    pub fitted: f64,
}

/// An isotonic map fitted on one route group's fit half, and everything it was fitted under:
/// the question, the group's key, the fit-half pairs and the map's knots. Advice only: nothing
/// in the ladder, a grant, a scope, a critical-write check or consent reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCalibrationMap {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub question: EntityId,
    pub key: RouteGroupKey,
    /// The fit-half pairs, in read order.
    pub fit: Vec<CalibrationPairRef>,
    /// Its knots in raw order, each raw probability strictly above the one before: each pooled
    /// block's lowest and highest raw probability at the block's label rate (once when they
    /// are one). A raw probability between two knots takes the line between them; one outside
    /// them takes the nearest end knot's fitted value.
    pub knots: Vec<MapKnot>,
}

/// Binary calibration of P(label) on one half, each pair weighing its label's noise weight:
/// the Brier score, mean (P - label)^2, and the equal-width reliability calibration error over
/// [`super::ECE_BINS`] bins, sum over bins of |sum P - sum label| / total (the per-seat
/// question evaluation's definitions).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationMetrics {
    pub brier_score: f64,
    pub calibration_error: f64,
}

/// What a fitted map accepts on the check half at one cut. A check pair is accepted when the
/// map's fitted confidence in its own answer reaches the cut: P(yes) for a yes, 1 - P(yes) for
/// a no, the fitted probability for any other answer; an abstention is never accepted. It is
/// wrong when a yes/no answer differs from its label, or another answer's label says it did
/// not hold.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceAtCut {
    /// One fitted level of the map: each distinct knot value is one cut, never a constant.
    pub cut: f64,
    /// The lowest raw probability the map fits to the cut.
    pub raw: f64,
    /// The check pairs accepted.
    pub accepted: usize,
    /// The accepted share of the check half's label weight.
    pub coverage: f64,
    /// The wrong share of the accepted label weight; none when nothing accepted weighs
    /// anything.
    pub accepted_error: Option<f64>,
}

/// Why a route group has no fitted map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteFitRefusal {
    /// The fit half holds fewer than `needed` pairs.
    TooFewFitPairs { needed: usize },
    /// Every fit-half pair's label weighs nothing.
    WeightlessFit,
}

/// A route group's map: fitted, with its check-half calibration and acceptance, or refused
/// with why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteFit {
    Fitted {
        map: RouteCalibrationMap,
        /// The check half's calibration at the fitted probabilities; none when it weighs
        /// nothing.
        fitted: Option<CalibrationMetrics>,
        /// Accepted error and coverage at each of the map's cuts, ascending; empty when the
        /// check half weighs nothing.
        acceptance: Vec<AcceptanceAtCut>,
    },
    Refused {
        reason: RouteFitRefusal,
    },
}

/// One route group: its key, the pairs on each half, the check half's calibration at the raw
/// probabilities (none when it weighs nothing) and its map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCalibrationGroup {
    pub key: RouteGroupKey,
    pub fit_pairs: usize,
    pub check_pairs: usize,
    pub raw: Option<CalibrationMetrics>,
    pub fit: RouteFit,
}

/// A question's calibration per route (route-conditioned calibration): its pairs grouped by
/// [`RouteGroupKey`] in read order, each group fitted on its fit half and measured on its
/// check half.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteCalibrationReport {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub question: EntityId,
    pub groups: Vec<RouteCalibrationGroup>,
    /// Every row the report's pairs were derived from, each once. A retained copy of it is
    /// released again only while each of them may leave.
    #[serde(skip)]
    pub derived_from: Vec<EntityId>,
}
