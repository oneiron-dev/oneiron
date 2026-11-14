//! The scorecard axis values one campaign judges (RESEARCH-0651 Tier 0).
//!
//! A candidate parameter set is compared with the incumbent on the held_out
//! slice: the engine's dominance rule decides first (in oneiron-bench, a later
//! PR), then a paired bootstrap on each Primary axis must show a 95 % lower
//! bound above 0, then a candidate whose commit touches a ruler path is
//! rejected. This module reads one named axis value off a scorecard and holds
//! the two-scorecard comparison the sealed check judges.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::scorecard::{RANKED_METRICS, Scorecard};

/// Which way an axis improves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxisDirection {
    /// Larger values are better.
    Higher,
    /// Smaller values are better.
    Lower,
}

/// The role of an axis in a campaign's metric set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxisRole {
    /// The candidate must clear it on held_out; the sealed check judges it.
    Primary,
    /// A floor the candidate must hold; the sealed check judges it.
    Floor,
    /// Reported but never judged.
    Cost,
}

/// One axis judged on two scorecards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AxisComparison {
    /// The axis name, as [`axis_value`] reads it.
    pub axis: String,
    /// The role of the axis in the campaign's metric set.
    pub role: AxisRole,
    /// Which way the axis improves.
    pub direction: AxisDirection,
    /// The symmetric dead band: a change of at most this much is a tie.
    pub tolerance: f64,
    /// The incumbent's value.
    pub incumbent: f64,
    /// The candidate's value.
    pub candidate: f64,
}

impl AxisComparison {
    /// The oriented change: positive means the candidate is better.
    pub fn delta(&self) -> f64 {
        match self.direction {
            AxisDirection::Higher => self.candidate - self.incumbent,
            AxisDirection::Lower => self.incumbent - self.candidate,
        }
    }

    /// True when the candidate is worse by more than the tolerance.
    pub fn is_worse_beyond_tolerance(&self) -> bool {
        -self.delta() > self.tolerance
    }
}

/// Every way an axis value can fail to read.
#[derive(Debug, Error)]
pub enum AxisError {
    /// The axis name is not one this crate reads.
    #[error("unknown axis: {axis}")]
    UnknownAxis {
        /// The unknown name.
        axis: String,
    },
    /// The scorecard holds no category minimum for the axis.
    #[error("missing category minimum for axis: {axis}")]
    MissingCategoryMin {
        /// The axis that needs it.
        axis: String,
    },
    /// The axis value is not finite.
    #[error("non-finite value for axis: {axis}")]
    NonFinite {
        /// The bad axis.
        axis: String,
    },
}

/// The scorecard value an axis name reads.
///
/// The six means read `scorecard.metrics`; `repeat_digest_equal` is 1.0 when
/// true, else 0.0; `min_<m>` reads the weakest category's value for the ranked
/// metric `<m>`; the two `search_p*_us` names read `scorecard.latency`.
pub fn axis_value(scorecard: &Scorecard, axis: &str) -> Result<f64, AxisError> {
    if let Some(name) = axis.strip_prefix("min_") {
        if !RANKED_METRICS.contains(&name) {
            return Err(AxisError::UnknownAxis {
                axis: axis.to_owned(),
            });
        }
        let entry = match scorecard.per_category_min.get(name) {
            Some(entry) => entry,
            None => {
                return Err(AxisError::MissingCategoryMin {
                    axis: axis.to_owned(),
                });
            }
        };
        if !entry.value.is_finite() {
            return Err(AxisError::NonFinite {
                axis: axis.to_owned(),
            });
        }
        return Ok(entry.value);
    }
    let value = match axis {
        "ndcg_at_10" => scorecard.metrics.ndcg_at_10,
        "mrr" => scorecard.metrics.mrr,
        "recall_at_5" => scorecard.metrics.recall_at_5,
        "recall_at_20" => scorecard.metrics.recall_at_20,
        "recall_at_budget" => scorecard.metrics.recall_at_budget,
        "abstention_f1" => scorecard.metrics.abstention_f1,
        "repeat_digest_equal" => {
            if scorecard.repeat_digest_equal {
                1.0
            } else {
                0.0
            }
        }
        "search_p50_us" => scorecard.latency.search_p50_us as f64,
        "search_p95_us" => scorecard.latency.search_p95_us as f64,
        _ => {
            return Err(AxisError::UnknownAxis {
                axis: axis.to_owned(),
            });
        }
    };
    if !value.is_finite() {
        return Err(AxisError::NonFinite {
            axis: axis.to_owned(),
        });
    }
    Ok(value)
}

/// True when the axis has per-query values (the five [`RANKED_METRICS`] names), so it can be bootstrapped.
pub fn is_per_query_axis(axis: &str) -> bool {
    RANKED_METRICS.contains(&axis)
}
