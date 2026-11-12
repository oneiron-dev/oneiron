//! Moved from `crates/oneiron/src/clipboard/world.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::ActSurface;
use oneiron_authority::authority::ModelOrder;
use oneiron_authority::authority::ReadLocation;
use oneiron_authority::authority::SealedCopies;
use oneiron_authority::authority::WorldPrivacy;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_WORLD;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains;
use oneiron_contracts::temporal::TimeRange;
use serde::Deserialize;
use serde::Serialize;

/// The engine-owned Clipboard role in one vault's namespace. It grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardWorld {
    pub world: EntityId,
}
