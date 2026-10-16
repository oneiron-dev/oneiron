//! Typed question records and shared outcome projection.

mod asks;
pub use asks::{AskAnswer, AskPrior, DecisionAsk, DecisionAsks};
pub mod catalogue;
mod codec;
mod generated;
pub use generated::{GeneratedDecisions, GeneratedMiss, GeneratedRung, GeneratedStep};
mod held;
pub use held::HeldLadder;
pub(crate) use held::{cut_text, fit_state};
mod ladder;
mod local;
mod media;
pub use media::*;
mod policy;
pub use local::{
    DecisionInput, DecisionRule, DecisionSeat, LabelClassifier, LocalDecisionSeat, RuleExpression,
};
pub mod questions;
mod read;
pub use read::DecisionReadProvider;
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
