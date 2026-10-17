//! The live task-type tree (ARCH-0079 #task-type, OF-541): data inside the
//! team-shape skill, so it forks and merges like one.
//!
//! The tree is one file, [`TASK_TYPE_TREE_FILE`], in the team-shape skill's
//! ordinary package. The tree in force for a project is its admitted
//! team-shape fork's (found by lineage among the project's skill forks),
//! else the vault skill's newest admitted revision, else the seeded tree. A
//! skill whose package carries no tree reads the seed: nothing is written on
//! a placement. A structural change is stored into an open local fork
//! through the existing fork/update door and goes in force once the
//! ordinary gate admits it; old stamps keep naming the version they were
//! placed at. There is no tree head table: the skill lineage is the head.

use std::collections::BTreeSet;

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill::{SkillLifecycle, skill_loadable};
use crate::skill_hub::{HubFile, HubPackage};
use crate::task_type::{
    PlacementDecisions, PlacementRequest, TaskTypeRef, TaskTypeTree, ensure_type_ref,
};
use crate::temporal::TimeRange;

use super::team_shape::team_shape_skill;
use super::widen_record::invalid;

/// The tree file inside the team-shape skill's package.
pub const TASK_TYPE_TREE_FILE: &str = "task-type-tree.json";

/// The tree in force for `project` (`None` is the vault tree).
///
/// # Errors
///
/// Storage errors, or a stored tree file that does not decode.
pub fn load_team_type_tree(vault: &Vault, project: Option<EntityId>) -> Result<TaskTypeTree> {
    let txn = vault.store.env.read_txn()?;
    load_team_type_tree_in_txn(vault, &txn, project)
}

/// [`load_team_type_tree`] in the caller's snapshot, so a placement and
/// the write it stamps read one tree.
pub(crate) fn load_team_type_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<TaskTypeTree> {
    let vault_skill = team_shape_skill()?;
    if let Some(project) = project
        && let Some(fork) = project_fork_in_txn(vault, txn, project, vault_skill)?
        && let Some(tree) = stored_tree_in_txn(vault, txn, &fork)?
    {
        return Ok(tree);
    }
    Ok(match vault_head_in_txn(vault, txn, vault_skill)? {
        Some(head) => stored_tree_in_txn(vault, txn, &head)?.unwrap_or_else(TaskTypeTree::seeded),
        None => TaskTypeTree::seeded(),
    })
}

/// The team-shape skill in force for `project`: its admitted fork, else the
/// vault skill's newest admitted revision. `None` when neither is loadable.
///
/// # Errors
///
/// Storage errors.
pub fn team_shape_skill_in_force(
    vault: &Vault,
    project: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let vault_skill = team_shape_skill()?;
    if let Some(project) = project
        && let Some(fork) = project_fork_in_txn(vault, &txn, project, vault_skill)?
    {
        return Ok(Some(fork));
    }
    vault_head_in_txn(vault, &txn, vault_skill)
}

/// Places a spawn once against `tree`: a requested stamp the tree accepts
/// is kept, anything else is placed through the placement skill's ladder
/// (the host's `decisions`, else its rule rung alone), and unsure is the
/// root.
pub(crate) fn place_in_tree(
    tree: &TaskTypeTree,
    requested: Option<&TaskTypeRef>,
    label: Option<String>,
    text: Option<String>,
    project: Option<EntityId>,
    decisions: Option<&PlacementDecisions<'_>>,
) -> TaskTypeRef {
    let mut request = PlacementRequest::new(label, text);
    if let Some(project) = project {
        request = request.with_project(project.to_hex());
    }
    ensure_type_ref(tree, requested, &request, decisions)
}

/// Writes `tree` into `fork`, an open local fork of the team-shape skill,
/// through the shared fork-package door: the fork keeps its own skill id and
/// parent edge, and re-enters the admission gate like any edit. The tree's
/// version must not fall behind the tree its parent carries; stamps placed
/// against older versions are never restamped.
///
/// # Errors
///
/// [`crate::error::ArtifactError::InvalidAgentDispatchInput`] for a fork
/// outside the team-shape lineage, a malformed tree or a version that moves
/// backwards; the fork door's own refusals; storage errors.
pub fn store_team_type_tree(
    vault: &Vault,
    fork: EntityId,
    tree: &TaskTypeTree,
    at: u64,
) -> Result<()> {
    validate_tree(tree)?;
    let txn = vault.store.env.read_txn()?;
    let record = vault.read_skill_record_in_txn(&txn, &fork)?;
    let parent = record
        .forked_from
        .ok_or_else(|| invalid("a stored type tree goes into a local fork"))?;
    if record.lifecycle_status != SkillLifecycle::Candidate {
        return Err(invalid("a stored type tree goes into an open fork"));
    }
    if !in_lineage_in_txn(vault, &txn, fork, team_shape_skill()?)? {
        return Err(invalid("fork is not in the team-shape skill's lineage"));
    }
    let parent_version = match vault.get_skill_record_in_txn(&txn, &parent)? {
        Some(_) => stored_tree_unchecked_in_txn(vault, &txn, &parent)?
            .map_or(TaskTypeTree::seeded().version, |stored| stored.version),
        None => TaskTypeTree::seeded().version,
    };
    if tree.version < parent_version {
        return Err(invalid(
            "a stored type tree never moves its version backwards",
        ));
    }
    let package = vault
        .runtime_skill_package_in_txn(&txn, &fork, &record)?
        .ok_or_else(|| invalid("team-shape fork has no stored source"))?;
    drop(txn);
    let content =
        serde_json::to_vec_pretty(tree).map_err(|_| invalid("type tree does not encode"))?;
    let mut files: Vec<HubFile> = package
        .files
        .into_iter()
        .filter(|file| file.path != TASK_TYPE_TREE_FILE)
        .collect();
    files.push(HubFile::new(TASK_TYPE_TREE_FILE, content));
    vault.write_shared_skill_fork_package(
        &fork,
        &HubPackage::new(record, files, package.capabilities),
        TimeRange { start: at, end: at },
        at,
    )
}

/// The newest admitted team-shape fork among the project's skill forks.
fn project_fork_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    vault_skill: EntityId,
) -> Result<Option<EntityId>> {
    let Some(record) = vault.visible_project_in_txn(txn, project)? else {
        return Ok(None);
    };
    for fork in record.skill_forks.iter().rev() {
        let Ok(fork) = EntityId::from_hex(fork) else {
            continue;
        };
        if vault
            .get_skill_record_in_txn(txn, &fork)?
            .is_some_and(|skill| skill_loadable(&skill))
            && in_lineage_in_txn(vault, txn, fork, vault_skill)?
        {
            return Ok(Some(fork));
        }
    }
    Ok(None)
}

/// Whether `skill`'s fork chain reaches `root`.
fn in_lineage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    root: EntityId,
) -> Result<bool> {
    let mut seen = BTreeSet::new();
    let mut cursor = Some(skill);
    while let Some(id) = cursor {
        if id == root {
            return Ok(true);
        }
        if !seen.insert(id) {
            return Ok(false);
        }
        cursor = vault
            .get_skill_record_in_txn(txn, &id)?
            .and_then(|record| record.forked_from);
    }
    Ok(false)
}

/// The vault skill's newest admitted revision, following its supersession
/// chain forward. `None` when no revision on the chain is loadable.
fn vault_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_skill: EntityId,
) -> Result<Option<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut cursor = vault_skill;
    let mut head = None;
    while seen.insert(cursor) {
        let Some(record) = vault.get_skill_record_in_txn(txn, &cursor)? else {
            break;
        };
        if skill_loadable(&record) {
            head = Some(cursor);
        }
        let mut next = None;
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &vault.store,
            txn,
            &cursor,
            crate::ports::EdgeDirection::In,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if !seen.contains(&peer) {
                next = Some(peer);
                break;
            }
        }
        match next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Ok(head)
}

/// The tree an admitted skill carries, if its package has one.
fn stored_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<TaskTypeTree>> {
    match vault.get_skill_record_in_txn(txn, skill)? {
        Some(record) if skill_loadable(&record) => stored_tree_unchecked_in_txn(vault, txn, skill),
        _ => Ok(None),
    }
}

/// The tree file in `skill`'s stored package, whatever its lifecycle: the
/// version floor a fork's new tree is checked against.
fn stored_tree_unchecked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<TaskTypeTree>> {
    let record = vault.read_skill_record_in_txn(txn, skill)?;
    let Some(package) = vault.runtime_skill_package_in_txn(txn, skill, &record)? else {
        return Ok(None);
    };
    let Some(file) = package
        .files
        .iter()
        .find(|file| file.path == TASK_TYPE_TREE_FILE)
    else {
        return Ok(None);
    };
    let tree: TaskTypeTree = serde_json::from_slice(&file.content)
        .map_err(|_| invalid("team-shape type tree does not decode"))?;
    validate_tree(&tree)?;
    Ok(Some(tree))
}

/// A tree is structurally whole: a root, and every parent a stored node.
fn validate_tree(tree: &TaskTypeTree) -> Result<()> {
    if tree.version == 0 {
        return Err(invalid("a type tree version starts at 1"));
    }
    if !tree.nodes.contains_key(crate::task_type::ROOT_NODE_ID) {
        return Err(invalid("a type tree has a root"));
    }
    if tree.nodes.iter().any(|(id, node)| {
        node.node_id != *id
            || node
                .parent
                .as_ref()
                .is_some_and(|parent| !tree.nodes.contains_key(parent))
    }) {
        return Err(invalid("every type node names a stored parent"));
    }
    Ok(())
}
