//! Moved from `crates/oneiron/src/graph_fs/snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A reference selects content, never authority. Historical references name
/// retained imported snapshots, not a local folder on the serving host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphFsReference {
    LiveHead,
    ForkHash { repo: EntityId, hash: String },
    RepoSnapshot { snapshot: EntityId },
}
