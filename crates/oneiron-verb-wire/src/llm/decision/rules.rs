//! Moved from `crates/oneiron/src/llm/decision/rules.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::model_decision::HostRuleRef;

/// What the Rule rung reports for the answer a standing row gives: certain of the answer
/// the owner gave (P(yes) 1 or 0 for yes/no, 1 for any other answer).
pub const RULE_CERTAINTY: f64 = 1.0;
