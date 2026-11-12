//! Moved from `crates/oneiron/src/graph_fs/snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_snapshot::ids::codebase_asset_entity_id as snapshot_asset_entity_id;
use oneiron_store::graph_fs::model::GraphFsEntry;
use oneiron_store::graph_fs::model::GraphFsFile;
use oneiron_store::graph_fs::model::GraphFsMount;
use oneiron_store::graph_fs::model::GraphFsOptions;
use oneiron_store::graph_fs::model::GraphFsPage;
use oneiron_store::graph_fs::paging::SealedPosition;
pub(crate) use oneiron_store::graph_fs::snapshot::*;
use oneiron_store::ports::point_read::PointRead;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// A reference selects content, never authority. Historical references name
/// retained imported snapshots, not a local folder on the serving host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphFsReference {
    LiveHead,
    ForkHash { repo: EntityId, hash: String },
    RepoSnapshot { snapshot: EntityId },
}
