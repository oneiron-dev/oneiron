//! Moved from `crates/oneiron/src/receipt/decision_asks.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::model_decision::DecisionAnswer;
use serde::Deserialize;
use serde::Serialize;

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

/// `vault.decisions.asks.confirm_grant`'s input: the owner's confirm of the
/// standing grant his reason drafted on one ask about a consent effect (FIX
/// 2975). The owner is the credential's, never a field here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAskConfirmGrantRequest {
    /// The ask's arrival number.
    pub seq: u64,
    /// The one-line notice shown beside the live grant, in the host's words.
    pub notice: String,
}

/// `vault.decisions.asks.climb`'s input: one open ask to move to the next
/// role on its chain with a live holder, up to its ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAskClimbRequest {
    /// The ask's arrival number.
    pub seq: u64,
}
