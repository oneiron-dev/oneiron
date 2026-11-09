//! Moved from `crates/oneiron/src/dreamer_consolidation/provenance.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_consolidation::kept_ask::KeptAsk;

/// One typed question's decision as a consolidation write keeps it: the
/// ladder's whole decision (all three answers, its pins, evidence versions,
/// principal and clock) and, when it went up the role chain, that ask.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptDecision {
    pub decision: crate::llm::decision::types::TypedDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<KeptAsk>,
}

impl KeptDecision {
    /// The answer the Dreamer acts on: the holder's when the decision went up
    /// the role chain, the ladder's otherwise. None while the ask waits.
    #[must_use]
    pub fn answer(&self) -> Option<&oneiron_store::model_decision::DecisionAnswer> {
        match &self.ask {
            Some(ask) => ask.answer.as_ref().map(|answer| &answer.answer),
            None => Some(&self.decision.answer),
        }
    }

    /// How sure the answer acted on is: a holder's answer is the answer.
    #[must_use]
    pub fn probability(&self) -> Option<f64> {
        match &self.ask {
            Some(ask) => ask.answer.as_ref().map(|_| 1.0),
            None => self.decision.probability,
        }
    }

    /// Whether the work this decides waits on a role's answer.
    #[must_use]
    pub fn waiting(&self) -> bool {
        self.answer().is_none()
    }
}
