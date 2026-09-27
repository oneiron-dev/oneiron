//! Typed question records and shared outcome projection.

mod codec;
mod local;
pub use local::{
    DecisionInput, DecisionRule, DecisionSeat, LabelClassifier, LocalDecisionSeat, RuleExpression,
};
pub mod questions;
mod types;

pub use types::*;
