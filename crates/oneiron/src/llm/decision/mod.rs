//! Typed question records and shared outcome projection.

mod answer_actor;
pub use answer_actor::AnswerActor;
pub(crate) use answer_actor::{erase_ask_actor_in_txn, erase_rule_actor_in_txn};
mod asks;
pub(crate) use asks::WORLD_PRIVACY_ASK_QUEUE;
pub use asks::{AskAnswer, AskPrior, DecisionAsk, DecisionAsks};
pub mod catalogue;
mod codec;
mod generated;
pub use generated::{
    DecisionWireLabels, GENERATED_SETTLEMENT_INVARIANT, GeneratedDecisions, GeneratedMiss,
    GeneratedRung, GeneratedStep,
};
mod held;
pub use held::HeldLadder;
pub use held::{cut_text, fit_reserve_state, fit_state};
mod ladder;
mod local;
mod locate;
pub use locate::*;
mod media;
pub use media::*;
mod media_ref;
pub use media_ref::*;
mod policy;
pub use local::{
    DecisionInput, DecisionRule, DecisionSeat, LabelClassifier, LocalDecisionSeat, RuleExpression,
};
pub mod questions;
mod read;
pub use read::{DecisionReadGate, DecisionReadProvider, GatedRead};
mod routine;
pub use routine::*;
mod rules;
pub use rules::{HostRule, HostRuleProvider, HostRuleRef, MAX_RULE_REASON_BYTES};
mod seat;
mod slides_policy;
mod types;

pub use ladder::*;
pub use policy::*;
pub use seat::{
    DecisionSeat as RemoteDecisionSeat, RemoteDecisionCapability, SeatAnswer, SeatFuture,
    SeatPhase, SeatRequest, decide_at_remote_seat, unit_text_may_leave_host,
};
pub use slides_policy::*;
pub use types::*;

#[cfg(test)]
mod tests;
