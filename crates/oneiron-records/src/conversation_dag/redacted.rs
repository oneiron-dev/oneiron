//! Moved from `crates/oneiron/src/conversation_dag/redacted.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPin {
    pub room: EntityId,
    pub parent: Option<EntityId>,
    pub session: Option<EntityId>,
    pub thread: bool,
    /// A PERSON byline needed for soft→hard escalation; dropped on hard purge.
    pub author: Option<EntityId>,
}
