//! The `vault.conversations.create` and `vault.conversations.turns.create`
//! rows' input and receipt types (OF-181). The Vault doors that write them
//! are the engine's (`core_write` in `oneiron`).

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::CoreWriteTextField;

/// A conversation to create. A body that names members also authors the
/// room's membership ledger, its creator and its role grants, as the
/// writing actor; a body with none is a plain put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConversationCreateInput {
    /// The conversation's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// Unix seconds; defaults to `learned_at`.
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    /// Unix seconds; defaults to `occurred_start`.
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    /// Unix seconds; defaults to now.
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    /// The conversation body: kind, members, roles, title and the rest.
    pub body: Value,
    /// Explicit text-index fields; when omitted, the body's top-level strings.
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// One TURN to put under a conversation, with its checked ChildOf edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConversationTurnCreateInput {
    /// The CONVERSATION the TURN belongs to.
    pub conversation: String,
    /// The TURN's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// The entity a core write stored: its id, its type, the learned time it
/// sampled and the body as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreEntityWriteReceipt {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: Value,
}

impl CoreEntityWriteReceipt {
    /// The receipt for `id`, of `entity_type`, learned at `learned_at`,
    /// with the body as stored.
    #[must_use]
    pub fn new(id: EntityId, entity_type: u8, learned_at: u64, body: Value) -> Self {
        Self {
            id: id.to_hex(),
            entity_type,
            learned_at,
            body,
        }
    }
}
