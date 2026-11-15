//! Moved from `crates/oneiron/src/reaction/outbound.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What the connector lane receives. Provider message addresses are resolved
/// by the adapter, never invented in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionOutboundAttempt {
    pub reaction: EntityId,
    pub connector: String,
    pub room_external_id: String,
    pub remove: bool,
}
