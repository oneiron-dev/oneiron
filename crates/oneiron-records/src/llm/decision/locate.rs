//! Moved from `crates/oneiron/src/llm/decision/locate.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::HumanAskReason;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// A Box or Point call's decisions: its presence step, then its coordinates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocatedDecision {
    /// The presence question's decision; none when the host words no presence question,
    /// and the coordinates were asked directly.
    pub presence: Option<TypedDecision>,
    /// The coordinate question's decision; none when presence did not start it.
    pub location: Option<TypedDecision>,
    /// The answer on the coordinate question's contract: the location's, its found
    /// absence after a confident no, or Abstain.
    pub answer: DecisionAnswer,
}

impl LocatedDecision {
    /// The decision that stands: the location's when it ran, else the presence step's.
    pub fn standing(&self) -> &TypedDecision {
        self.location
            .as_ref()
            .or(self.presence.as_ref())
            .expect("a located decision ran a step")
    }

    /// Why the call has no answer: the standing step's reason, or Uncertain for a presence
    /// answer inside its band. None when it has one.
    pub fn human_ask(&self) -> Option<HumanAskReason> {
        (self.answer == DecisionAnswer::Abstain).then(|| {
            self.standing()
                .human_ask
                .unwrap_or(HumanAskReason::Uncertain)
        })
    }

    /// The decision that stands, and the presence step beside it when the location
    /// stands.
    pub fn split(self) -> (TypedDecision, Option<TypedDecision>) {
        match (self.location, self.presence) {
            (Some(location), presence) => (location, presence),
            (None, Some(presence)) => (presence, None),
            (None, None) => unreachable!("a located decision ran a step"),
        }
    }
}
