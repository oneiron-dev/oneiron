//! Moved from `crates/oneiron/src/note/files/source.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
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
