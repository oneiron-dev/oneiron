//! Moved from `crates/oneiron/src/agent_dispatch/comm_widen.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who answers a child's widen ask: its real dispatch parent's agent, or,
/// for a dispatch with no agent parent, the vault owner (CALLS W1); no one
/// once that actor was erased (FIX 3520).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommWidenRecipient {
    Agent(EntityId),
    Owner(EntityId),
    Erased,
}

impl CommWidenRecipient {
    /// The actor, while it is not erased.
    pub const fn actor(self) -> Option<EntityId> {
        match self {
            Self::Agent(actor) | Self::Owner(actor) => Some(actor),
            Self::Erased => None,
        }
    }

    /// Names no one in place of `actor`; whether it named it.
    fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.actor() == Some(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

/// Where one request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommWidenState {
    Pending,
    Approved,
    Declined,
}
