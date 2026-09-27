//! Typed question records and shared outcome projection.

mod codec;
mod ladder;
mod local;
mod policy;
pub use local::{
    DecisionInput, DecisionRule, DecisionSeat, LabelClassifier, LocalDecisionSeat, RuleExpression,
};
pub mod questions;
mod seat;
mod types;

pub use ladder::*;
pub use policy::*;
pub use seat::*;
pub use types::*;

#[cfg(test)]
mod tests;
