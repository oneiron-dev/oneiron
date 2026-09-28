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
mod slides_policy;
mod types;

pub use ladder::*;
pub use policy::*;
pub use seat::{
    DecisionSeat as RemoteDecisionSeat, SeatAnswer, SeatFuture, SeatPhase, SeatRequest,
    decide_at_remote_seat,
};
pub use slides_policy::*;
pub use types::*;

#[cfg(test)]
mod tests;
