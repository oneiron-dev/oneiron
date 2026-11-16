//! Moved from `crates/oneiron/src/clipboard/world.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The engine-owned Clipboard role in one vault's namespace. It grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardWorld {
    pub world: EntityId,
}
