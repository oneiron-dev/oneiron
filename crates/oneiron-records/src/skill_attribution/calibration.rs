//! Moved from `crates/oneiron/src/skill_attribution/calibration.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The rule a batch's target was chosen under. A batch keeps it, so a later
/// rule can tell its targets apart.
pub const UNCLEAR_FLOOR_FITTER_VERSION: u32 = 1;

/// Where one audited case's answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAnswerSource {
    /// The host's model tier, through the shared decision ladder.
    Model,
    /// The deterministic rule tier.
    Rule,
    /// A settled amendment cause, answered without asking a judge.
    SettledCause,
    /// No judge was asked: the amendment's cause was unsettled.
    NotJudged,
}

/// One region's answer as the judge gave it, before any floor or lane rule
/// held it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawAnswer {
    /// The label it chose, as its wire string; `None` when it chose none.
    pub label: Option<String>,
    /// Its probability for that label; `None` when it gave none.
    pub confidence: Option<f64>,
}

/// The floor one batch argued for, or why it argued for none.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FloorFit {
    /// The floor that scored best on the batch's judged cases: `passed` of
    /// `judged` answered right under it.
    Target {
        floor: f32,
        passed: u64,
        judged: u64,
    },
    /// No case a model answered under a known revision.
    NoJudgedCase,
    /// Every candidate floor scored the same, so the batch says nothing about
    /// where the floor sits.
    Uninformative,
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a unit-interval probability narrowed to the judge's f32 confidence"
)]
pub fn narrow(probability: f64) -> f32 {
    probability as f32
}
