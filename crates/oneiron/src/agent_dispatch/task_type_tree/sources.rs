//! The selected project tree and its entity reads from one caller snapshot.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::skill::SkillContentHash;
use crate::skill_hub::HubRef;
use crate::{EntityId, Vault};

use super::{
    Reads, SkillRecord, TaskTypeTree, invalid, skill_loadable, tree_and_file_in_force_in_txn,
    validate_tree,
};

/// A single tree selection, not a read grant or a proof of source readability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourcedTeamTypeTree {
    pub tree: TaskTypeTree,
    /// The exact file that supplied the tree; `None` for the code seed.
    pub file: Option<SelectedTreeFile>,
    /// The complete entity-row inventory, or `None` if any input is unnameable.
    pub source_rows: Option<Vec<EntityId>>,
    /// The entity portion alone. A separate root lookup is still not covered.
    pub entity_rows: Option<Vec<EntityId>>,
    /// The root lookup's audit metadata, kept separate from entity-row sources.
    pub root_lookup: Option<HubRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedTreeFile {
    pub head: EntityId,
    pub package_hash: SkillContentHash,
    pub file_hash: [u8; 32],
}

/// Selects the actual project tree once, in the caller's snapshot or writer.
pub(crate) fn load_team_type_tree_with_sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<SourcedTeamTypeTree> {
    let (root, root_lookup) = super::super::team_shape::team_shape_root_sourced_in_txn(vault, txn)?;
    let mut reads = Reads::Named(BTreeSet::new());
    let (tree, file) = tree_and_file_in_force_in_txn(vault, txn, project, root, &mut reads)?;
    let entity_rows = reads.into_rows();
    // An alias/pin lookup cannot be represented by entity-row IDs alone.
    let source_rows = root_lookup.is_none().then(|| entity_rows.clone()).flatten();
    Ok(SourcedTeamTypeTree {
        tree,
        file,
        source_rows,
        entity_rows,
        root_lookup,
    })
}

pub(super) fn stored_tree_with_file_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<(TaskTypeTree, Option<SelectedTreeFile>)>> {
    let record = vault.get_skill_record_in_txn(txn, skill)?;
    if record.is_some() {
        reads.note(*skill);
    }
    match record {
        Some(record) if skill_loadable(&record) => {
            stored_tree_unchecked_with_file_in_txn(vault, txn, skill, reads)
        }
        _ => Ok(None),
    }
}

/// The tree file in `skill`'s stored package, whatever its lifecycle: the
/// version floor a fork's new tree is checked against.
pub(super) fn stored_tree_unchecked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<TaskTypeTree>> {
    Ok(
        stored_tree_unchecked_with_file_in_txn(vault, txn, skill, reads)?
            .map(|selected| selected.0),
    )
}

fn stored_tree_unchecked_with_file_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<(TaskTypeTree, Option<SelectedTreeFile>)>> {
    let record = vault.read_skill_record_in_txn(txn, skill)?;
    reads.note(*skill);
    let package = vault.runtime_skill_package_in_txn(txn, skill, &record)?;
    if reads.naming() {
        note_carrier_in_txn(vault, txn, skill, &record, package.is_some(), reads);
    }
    let Some(package) = package else {
        return Ok(None);
    };
    let Some(file) = package
        .files
        .iter()
        .find(|file| file.path == super::TASK_TYPE_TREE_FILE)
    else {
        return Ok(None);
    };
    let tree: TaskTypeTree = serde_json::from_slice(&file.content)
        .map_err(|_| invalid("team-shape type tree does not decode"))?;
    validate_tree(&tree)?;
    let source = reads
        .naming()
        .then(|| record.content_hash)
        .flatten()
        .map(|package_hash| SelectedTreeFile {
            head: *skill,
            package_hash,
            file_hash: *blake3::hash(&file.content).as_bytes(),
        });
    Ok(Some((tree, source)))
}

/// Notes the replicated source carrier that served `skill`'s package, when
/// one did, by the probe an export names it by (SCAN C022), in the same
/// read. The skill's own package row is the skill's. A carrier looked up
/// that served nothing, or a probe that fails, leaves the rows unknown: the
/// lookup may have read a row it then refused (FIX 7103).
fn note_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
    served: bool,
    reads: &mut Reads,
) {
    match vault.export_hub_package_carrier_in_txn(txn, skill, record) {
        Ok(None) => {}
        Ok(Some(carrier)) if served => reads.note(carrier),
        Ok(Some(_)) | Err(_) => reads.unknown(),
    }
}
