//! OF-493's role-holder doors (Q3 by role): the wire shapes a person or a
//! bound agent uses to answer the decision asks put to its role, to pass one
//! up its chain, and to list the open asks put to it.
//!
//! The engine's `DecisionAnswer` rides inside unchanged, decoded through its
//! own serde and shown to a schema as any JSON value. No holder, role, kind
//! or clock is a field here: the server's door takes the actor and its class
//! from the credential, and the vault reads the role's holders again.

use serde::{Deserialize, Serialize};

use crate::llm::decision::DecisionAnswer;

/// The most asks one `self.decisions.asks` page holds.
pub const DECISION_ASK_PAGE_MAX: usize = 500;

/// A `self.decisions.asks` page's size when the request names none.
pub const DECISION_ASK_PAGE: usize = 50;

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

/// `self.decisions.asks`'s input: a page of the open asks put to the
/// caller, oldest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAskListRequest {
    /// The arrival number the page starts after; from the first when absent.
    #[serde(default)]
    pub after: Option<u64>,
    /// At most this many asks, 1 to [`DECISION_ASK_PAGE_MAX`];
    /// [`DECISION_ASK_PAGE`] when absent.
    #[serde(default)]
    pub limit: Option<usize>,
}

impl DecisionAskListRequest {
    /// The page size this request asks for, inside the page bounds.
    #[must_use]
    pub fn page_limit(&self) -> usize {
        self.limit
            .unwrap_or(DECISION_ASK_PAGE)
            .clamp(1, DECISION_ASK_PAGE_MAX)
    }
}
