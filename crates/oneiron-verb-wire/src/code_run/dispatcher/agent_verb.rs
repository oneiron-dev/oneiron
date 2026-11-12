//! Moved from `crates/oneiron/src/code_run/dispatcher/agent_verb.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// How an operation's send went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretUseStatus {
    /// The provider answered; `result` is its answer.
    Answered,
    /// The operation failed; `failure` says why.
    Failed,
    /// It ran, but its result could not be cleared of the value, so none
    /// comes back.
    Withheld,
}

/// `self.use`'s answer. It never holds the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseAnswer {
    pub status: SecretUseStatus,
    /// The operation's answer, when it answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Why it failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub receipt: SecretUseRecord,
}

/// One use's receipt: what was used, by what, and how it went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseRecord {
    pub handle: String,
    /// The secret's rotation generation when it was used.
    pub generation: u32,
    /// The custody record whose value the send actually presented, as its
    /// door released it (FIX 8052); distinct from the admitted handle.
    /// `None` when nothing was sent, or nothing said what was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_custody: Option<EntityId>,
    /// The generation the send actually presented; distinct from the
    /// admitted generation. `None` when nothing said what was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_generation: Option<u32>,
    /// The effector the binding names, such as `connector:slack`.
    pub effector: String,
    pub operation: String,
    /// The Gate record that keeps it, `gate:<hex>`.
    pub decision: String,
    pub used_at: u64,
}
