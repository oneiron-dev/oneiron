//! Moved from `crates/oneiron/src/llm/decision/rules.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::decision_rule_rows::HostRule;
use oneiron_store::model_decision::DecisionAnswer;
pub use oneiron_store::model_decision::HostRuleRef;
use oneiron_store::model_decision::ProviderDecision;

/// What the Rule rung reports for the answer a standing row gives: certain of the answer
/// the owner gave (P(yes) 1 or 0 for yes/no, 1 for any other answer).
pub const RULE_CERTAINTY: f64 = 1.0;

impl HostRule {
    /// The Rule rung's answer from this row.
    fn decision(&self) -> ProviderDecision {
        let probability = match self.answer {
            DecisionAnswer::Noul(false) => 1.0 - RULE_CERTAINTY,
            _ => RULE_CERTAINTY,
        };
        ProviderDecision {
            answer: self.answer.clone(),
            probability: Some(probability),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        }
    }
}
