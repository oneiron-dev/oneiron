//! Moved from `crates/oneiron/src/connector_key/tool_remember.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Engine-resolved scope of the call, frozen with its request. `None` project
/// means this call has no project; it is not a vault-wide selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorToolRememberContext {
    /// Filled only by preparation against the current native connector key.
    pub connection: Option<EntityId>,
    pub project: Option<EntityId>,
    pub lineage: Option<[u8; 32]>,
}
