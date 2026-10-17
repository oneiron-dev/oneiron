//! OF-493's role-holder doors (Q3 by role): the wire shapes a person or a
//! bound agent uses to answer a decision ask put to its role and to pass one
//! up its chain. Its list of the open asks at its roles takes no input.
//!
//! The engine's `DecisionAnswer` rides inside unchanged, decoded through its
//! own serde and shown to a schema as any JSON value. No holder, role, kind
//! or clock is a field here: the server's door takes the actor and its class
//! from the credential, and the vault reads the role's holders again.

use serde::{Deserialize, Serialize};

use crate::llm::decision::DecisionAnswer;

/// `vault.decisions.asks.answer`'s input: the caller's answer to one ask, as
/// a holder of the role the ask is at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAskAnswerRequest {
    /// The ask's arrival number.
    pub seq: u64,
    /// The engine's `DecisionAnswer`, one the ask's question contract
    /// accepts: `{"kind":"noul","value":true}`,
    /// `{"kind":"choice","value":"<option>"}`, `{"kind":"score","value":0.7}`,
    /// `{"kind":"box","value":{"top","bottom","left","right"}}` or
    /// `{"kind":"point","value":{"x","y"}}`. An abstention is refused.
    #[schemars(with = "serde_json::Value")]
    pub answer: DecisionAnswer,
}

/// `vault.decisions.asks.climb`'s input: one open ask to move to the next
/// role on its chain with a live holder, up to its ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAskClimbRequest {
    /// The ask's arrival number.
    pub seq: u64,
}
