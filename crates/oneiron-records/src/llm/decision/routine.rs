//! Moved from `crates/oneiron/src/llm/decision/routine.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::decision::locate::LocatedDecision;
use oneiron_base::error::Result;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::HumanAskReason;
use oneiron_store::model_decision::ImageBox;
use oneiron_store::model_decision::invalid;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// The reserved option a decider picks when no candidate fits.
pub const ROUTINE_NONE: &str = "NONE";

/// The reserved option a decider picks to look again before it chooses.
pub const ROUTINE_REOBSERVE: &str = "reobserve";

/// The reserved option a decider picks to hand the step back to the planner.
pub const ROUTINE_ASK_UP: &str = "too complicated, ask up";

/// NONE or reobserve answers in a row before the next observation takes a screenshot
/// (EIRI-ARCH-0002: "the decider returns NONE or reobserve twice").
pub const ROUTINE_MISSES_BEFORE_SCREENSHOT: u32 = 2;

/// What the driver does with a routine step's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutineOutcome {
    /// The decider picked this candidate: the driver takes its step on it.
    Act { candidate: String },
    /// The step's target in the screenshot: the driver acts at `x`, `y` (fractions of
    /// the image from its top-left), the point answered or the centre of `found`.
    Point {
        x: f64,
        y: f64,
        found: Option<ImageBox>,
    },
    /// No candidate fits, or the target is not in the screenshot.
    None,
    /// Look again before choosing.
    Reobserve,
    /// The step goes back to the planner: the decider chose to ask up (no reason), or the
    /// ladder gave no answer (`reason` says why: uncertain, cut by the clock, no rung).
    AskUp { reason: Option<HumanAskReason> },
}

impl RoutineOutcome {
    /// The routine reading of `decision`, a typed decision over a routine contract.
    pub fn of(decision: &TypedDecision) -> Result<Self> {
        Self::read(&decision.answer, decision.human_ask)
    }

    /// The routine reading of a located step: act at its point, NONE for its found
    /// absence, or ask up.
    pub fn of_located(located: &LocatedDecision) -> Result<Self> {
        Self::read(&located.answer, located.human_ask())
    }

    /// The routine reading of an answer, and the reason the ladder gave none.
    fn read(answer: &DecisionAnswer, human_ask: Option<HumanAskReason>) -> Result<Self> {
        Ok(match answer {
            DecisionAnswer::Choice(choice) if choice == ROUTINE_NONE => Self::None,
            DecisionAnswer::Choice(choice) if choice == ROUTINE_REOBSERVE => Self::Reobserve,
            DecisionAnswer::Choice(choice) if choice == ROUTINE_ASK_UP => {
                Self::AskUp { reason: None }
            }
            DecisionAnswer::Choice(choice) => Self::Act {
                candidate: choice.clone(),
            },
            DecisionAnswer::Box(Some(found)) => {
                let (x, y) = found.centre();
                Self::Point {
                    x,
                    y,
                    found: Some(*found),
                }
            }
            DecisionAnswer::Point(Some(point)) => Self::Point {
                x: point.x,
                y: point.y,
                found: None,
            },
            DecisionAnswer::Box(None) | DecisionAnswer::Point(None) => Self::None,
            DecisionAnswer::Abstain => Self::AskUp { reason: human_ask },
            DecisionAnswer::Noul(_) | DecisionAnswer::Score(_) => {
                return Err(invalid("not a routine answer"));
            }
        })
    }

    /// Whether the step found nothing to act on yet: NONE or reobserve.
    pub fn misses(&self) -> bool {
        matches!(self, Self::None | Self::Reobserve)
    }
}

/// The NONE and reobserve answers one subgoal's steps gave in a row: after
/// [`ROUTINE_MISSES_BEFORE_SCREENSHOT`] of them the next observation takes a screenshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineTrail {
    pub misses: u32,
}

impl RoutineTrail {
    /// Records `outcome`; true when the next observation takes a screenshot.
    pub fn record(&mut self, outcome: &RoutineOutcome) -> bool {
        self.misses = if outcome.misses() {
            self.misses.saturating_add(1)
        } else {
            0
        };
        self.misses >= ROUTINE_MISSES_BEFORE_SCREENSHOT
    }
}
