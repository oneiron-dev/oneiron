//! The owner's task-type tree doors (DOOR-111, OF-541): store an authored
//! tree on an open team-shape fork, and read the tree in force or one kept
//! version.
//!
//! Storing is candidate storage only. The fork keeps its lifecycle and goes
//! in force when the ordinary admission gate admits it; the receipt says
//! whether it is in force, and nothing here admits, flips a lifecycle or
//! registers a fork.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    load_team_type_tree, load_team_type_tree_at, store_team_type_tree, team_shape_skill_in_force,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::task_type::{ROOT_NODE_ID, TaskTypeNode, TaskTypeRef, TaskTypeTree, TreeScope};
use crate::{EntityId, Vault};

/// The highest version an authored tree may carry: the learning cell's type
/// stamp holds a `u32` version, so a higher one could not be read back as
/// the same stamp.
pub const FIXTURE_TREE_VERSION_MAX: u64 = u32::MAX as u64;

/// What an authored structure must be, said on every refusal of one.
const STRUCTURE_FIX: &str = "Author one root node `root` with no parent, unique non-empty node ids, and every other node's parent an authored node.";

/// A type stamp on the wire: one node in one version of the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TypeStamp {
    pub node_id: String,
    pub tree_version: u64,
}

impl From<&TaskTypeRef> for TypeStamp {
    fn from(stamp: &TaskTypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: stamp.tree_version,
        }
    }
}

/// One authored node: structure only. The root is the one node with no
/// parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeNodeSpec {
    pub node_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub name: String,
}

/// An authored tree for an open local fork of the team-shape skill, at the
/// version it is stored as. Its measured counters start at zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeTreePin {
    pub fork_ref: EntityId,
    pub tree_version: u64,
    pub nodes: Vec<TaskTypeNodeSpec>,
}

/// The vault's tree, or a project's: in force, or the kept tree at one
/// version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeTreeRead {
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    #[serde(default)]
    pub tree_version: Option<u64>,
}

/// One node as the tree holds it; not live once it merged away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeNodeView {
    pub node_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub name: String,
    pub live: bool,
}

/// A tree's structure: its version, its root stamp and every node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreeView {
    pub tree_version: u64,
    pub root: TypeStamp,
    pub nodes: Vec<TaskTypeNodeView>,
}

impl From<&TaskTypeTree> for TaskTypeTreeView {
    fn from(tree: &TaskTypeTree) -> Self {
        Self {
            tree_version: tree.version,
            root: TypeStamp::from(&tree.root_ref()),
            nodes: tree
                .nodes
                .values()
                .map(|node| TaskTypeNodeView {
                    node_id: node.node_id.clone(),
                    parent: node.parent.clone(),
                    name: node.name.clone(),
                    live: node.is_live(),
                })
                .collect(),
        }
    }
}

/// The tree stored on the fork, and whether that fork is the vault's
/// team-shape skill in force: a stored tree is a candidate until the gate
/// admits its fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreePinReceipt {
    pub fork_ref: EntityId,
    pub stored: TaskTypeTreeView,
    pub in_force: bool,
}

/// The tree read (`None` when no kept tree is at the version asked) and the
/// team-shape skill in force for the scope read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreeReadReply {
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    #[serde(default)]
    pub in_force_skill_ref: Option<EntityId>,
    #[serde(default)]
    pub tree: Option<TaskTypeTreeView>,
}

/// Stores an authored task-type tree on `input.fork_ref`, an open local fork
/// of the team-shape skill, as the owner, through the tree store (which
/// refuses a fork outside the lineage, a fork no longer open and a version
/// behind its parent's tree). The receipt says whether the fork is in force.
///
/// # Errors
///
/// `BAD_REQUEST` for a version outside `1..=FIXTURE_TREE_VERSION_MAX` or a
/// malformed structure, naming the offending node; the tree store's
/// refusals; a stale owner proof; storage errors.
pub fn pin_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TaskTypeTreePin,
) -> MemoryResult<TaskTypeTreePinReceipt> {
    owner.revalidate(vault)?;
    let version = input.tree_version;
    if !(1..=FIXTURE_TREE_VERSION_MAX).contains(&version) {
        return Err(MemoryError::bad_request_with(
            format!("tree_version {version} is outside 1..={FIXTURE_TREE_VERSION_MAX}"),
            &["An authored tree's version is at least 1 and fits a u32 type stamp."],
        ));
    }
    check_structure(&input.nodes)?;
    let tree = authored_tree(version, &input.nodes);
    store_team_type_tree(vault, input.fork_ref, &tree, crate::unix_seconds_now())?;
    let in_force = team_shape_skill_in_force(vault, None)? == Some(input.fork_ref);
    Ok(TaskTypeTreePinReceipt {
        fork_ref: input.fork_ref,
        stored: TaskTypeTreeView::from(&tree),
        in_force,
    })
}

/// Reads, as the owner, the task-type tree in force for the vault or
/// `project_ref`, or the kept tree at `tree_version` as it was placed in,
/// never restamped; and the team-shape skill in force there.
///
/// # Errors
///
/// A stale owner proof; a stored tree that does not decode; storage errors.
pub fn read_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TaskTypeTreeRead,
) -> MemoryResult<TaskTypeTreeReadReply> {
    owner.revalidate(vault)?;
    let tree = match input.tree_version {
        None => Some(load_team_type_tree(vault, input.project_ref)?),
        Some(version) => load_team_type_tree_at(vault, input.project_ref, version)?,
    };
    Ok(TaskTypeTreeReadReply {
        project_ref: input.project_ref,
        in_force_skill_ref: team_shape_skill_in_force(vault, input.project_ref)?,
        tree: tree.as_ref().map(TaskTypeTreeView::from),
    })
}

/// An authored structure is whole: unique non-empty ids, the root
/// [`ROOT_NODE_ID`] the one node with no parent, every parent an authored
/// node, and every parent chain reaching the root.
fn check_structure(nodes: &[TaskTypeNodeSpec]) -> MemoryResult<()> {
    let refused = |message: String| MemoryError::bad_request_with(message, &[STRUCTURE_FIX]);
    let mut parents: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for node in nodes {
        let id = node.node_id.as_str();
        if id.is_empty() {
            return Err(refused("a task-type node id is empty".to_owned()));
        }
        if parents.insert(id, node.parent.as_deref()).is_some() {
            return Err(refused(format!("task-type node {id:?} is authored twice")));
        }
    }
    if !parents.contains_key(ROOT_NODE_ID) {
        return Err(refused(format!(
            "the tree has no root node {ROOT_NODE_ID:?}"
        )));
    }
    for (id, parent) in &parents {
        match parent {
            None if *id != ROOT_NODE_ID => {
                return Err(refused(format!(
                    "task-type node {id:?} has no parent; only {ROOT_NODE_ID:?} is the root"
                )));
            }
            Some(_) if *id == ROOT_NODE_ID => {
                return Err(refused(format!("the root {ROOT_NODE_ID:?} names a parent")));
            }
            Some(parent) if !parents.contains_key(parent) => {
                return Err(refused(format!(
                    "task-type node {id:?} names parent {parent:?}, which is not an authored node"
                )));
            }
            _ => {}
        }
    }
    // A chain that reaches the root takes fewer steps than there are nodes;
    // one that does not loops.
    let mut rooted = BTreeSet::from([ROOT_NODE_ID]);
    for id in parents.keys() {
        let mut chain = Vec::new();
        let mut cursor = *id;
        while !rooted.contains(cursor) {
            if chain.len() == parents.len() {
                return Err(refused(format!(
                    "task-type node {id:?} never reaches the root: its parents loop"
                )));
            }
            chain.push(cursor);
            cursor = parents
                .get(cursor)
                .copied()
                .flatten()
                .unwrap_or(ROOT_NODE_ID);
        }
        rooted.extend(chain);
    }
    Ok(())
}

/// The authored nodes as a vault-scoped tree at `version`: structure only,
/// with no seed, split or merge metadata and every counter at zero.
fn authored_tree(version: u64, nodes: &[TaskTypeNodeSpec]) -> TaskTypeTree {
    TaskTypeTree {
        version,
        scope: TreeScope::Vault,
        nodes: nodes
            .iter()
            .map(|node| {
                let stored = TaskTypeNode {
                    node_id: node.node_id.clone(),
                    parent: node.parent.clone(),
                    name: node.name.clone(),
                    seed: None,
                    split_axis: None,
                    split_winner: None,
                    merged_into: None,
                    receipt_count: 0,
                    held_out_runs: 0,
                    held_out_wins: 0,
                    decision_wins: BTreeMap::new(),
                };
                (node.node_id.clone(), stored)
            })
            .collect(),
    }
}
