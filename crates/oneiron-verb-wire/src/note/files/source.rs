//! Moved from `crates/oneiron/src/note/files/source.rs` (lib split W1: wire types below the lib).
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

/// One file of a Files source, as a later search, action or peer names it:
/// the source (its install and world with it) and the path under the
/// folder. The ledger's hashes are its revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileHandle {
    pub source: EntityId,
    pub path: String,
}
