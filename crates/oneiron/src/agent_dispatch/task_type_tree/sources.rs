//! The selected project tree and its entity reads from one caller snapshot.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::skill_hub::HubRef;
use crate::{EntityId, Vault};

use super::{Reads, TaskTypeTree, tree_in_force_with_root_in_txn};

/// A single tree selection, not a read grant or a proof of source readability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourcedTeamTypeTree {
    pub tree: TaskTypeTree,
    /// The complete entity-row inventory, or `None` if any input is unnameable.
    pub source_rows: Option<Vec<EntityId>>,
    /// The root lookup's audit metadata, kept separate from entity-row sources.
    pub root_lookup: Option<HubRef>,
}

/// Selects the actual project tree once, in the caller's snapshot or writer.
pub(crate) fn load_team_type_tree_with_sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<SourcedTeamTypeTree> {
    let (root, root_lookup) = super::super::team_shape::team_shape_root_sourced_in_txn(vault, txn)?;
    let mut reads = Reads::Named(BTreeSet::new());
    // An alias/pin lookup cannot be represented by entity-row IDs alone.
    if root_lookup.is_some() {
        reads.unknown();
    }
    let tree = tree_in_force_with_root_in_txn(vault, txn, project, root, &mut reads)?;
    Ok(SourcedTeamTypeTree {
        tree,
        source_rows: reads.into_rows(),
        root_lookup,
    })
}
