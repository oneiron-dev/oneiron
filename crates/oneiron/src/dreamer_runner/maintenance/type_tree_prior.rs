//! The project tree's donor prior (ARCH-0079 #task-type, OF-420, FIX 5176):
//! a thin leaf of a project's own tree borrows the vault tree's counts on the
//! same leaf path, weighted, and the weight fades as the leaf's own runs come
//! in (CALLS "FIX 5176 PROJECT_TREE_DONOR_PRIOR").
//!
//! The prior is a read and nothing else: the blended counts live only inside
//! [`donor_prior_winner`], and no stored count, receipt, evidence row,
//! package or journal row ever holds them. The donor is the vault's current
//! tree, its counts recounted for the pass on the vault's own fit runs
//! ([`DonorTree::of_vault`]), so no project on a fork of its own, and no
//! reserved leader, reaches it.
//!
//! The live planner borrows on the same path at the same weight
//! ([`donor_weight`], FIX 5496): there the donor is the vault's stored tree
//! in force, and what it lends is measured learning, not decision counts.
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::type_tree_upkeep::{TypeEvidence, recount};
use crate::agent_dispatch::{load_team_type_tree_in_txn, team_shape_skill_in_force_in_txn};
use crate::skill_optimize::held_out_receipts;
use crate::task_type::{
    DecisionAxis, SPLIT_MIN_RUNS_PER_WINNER, THIN_LEAF_MIN_RECEIPTS, TaskTypeNode, TaskTypeTree,
    TreeScope,
};
use crate::team::TeamReceipt;
use crate::{EntityId, Result, Vault};

/// The weight the donor's counts carry on a project leaf with no runs of its
/// own. It fades linearly to nothing at [`THIN_LEAF_MIN_RECEIPTS`] own
/// receipts: `q = W * max(0, 1 - r / THIN_LEAF_MIN_RECEIPTS)`.
pub(crate) const PROJECT_TREE_DONOR_WEIGHT: f64 = 0.25;

/// The donor one pass lends to its project tree reads: the vault team-shape
/// head in force, the version of its tree, and that tree's structure counted
/// on the vault's own fit runs.
pub(super) struct DonorTree {
    pub(super) skill: EntityId,
    pub(super) version: u64,
    pub(super) tree: TaskTypeTree,
}

impl DonorTree {
    /// The vault's current tree, with its head read in the same snapshot,
    /// recounted on `settled` as the vault tree counts them: each team placed
    /// in the vault tree (no project, or a project with no fork of its own in
    /// force), less every team of a leader in the head's reserve. `None` when
    /// no head is in force.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored tree that does not decode.
    pub(super) fn of_vault(vault: &Vault, settled: &[TeamReceipt]) -> Result<Option<Self>> {
        let (skill, structure) = {
            let txn = vault.store.env.read_txn()?;
            let Some(skill) = team_shape_skill_in_force_in_txn(vault, &txn, None)? else {
                return Ok(None);
            };
            (skill, load_team_type_tree_in_txn(vault, &txn, None)?)
        };
        let reserved: BTreeSet<String> = held_out_receipts(vault, &skill)?.into_iter().collect();
        let (_, fit) = vault.vault_type_evidence(settled, &reserved)?;
        let rows: Vec<&TypeEvidence> = fit.iter().collect();
        let (tree, _) = recount(&structure, &rows);
        Ok(Some(Self {
            skill,
            version: tree.version,
            tree,
        }))
    }
}

/// The shared FIX 5176/5496 prior: the winner a read of `axis` under
/// `node_id` in `project_tree` takes with `donor`, the vault tree, lent.
///
/// It blends only on a live leaf of a project's own tree with fewer than
/// [`THIN_LEAF_MIN_RECEIPTS`] own receipts whose exact path the donor holds
/// as a live leaf: the same chain of node ids, split axes and raw split
/// winners from the same root (names and versions aside; no ancestor of
/// another tree, no subtree summed, no name matched). There the counts read
/// are `own + q * donor_own` (the donor leaf's own stored counts, never its
/// parents' or its own prior), and the strict leader with at least
/// [`SPLIT_MIN_RUNS_PER_WINNER`] weighted runs wins. Anywhere else, and on a
/// tie or too little weighted mass, it is
/// [`TaskTypeTree::effective_winner`], today's read.
#[must_use]
pub(crate) fn donor_prior_winner(
    project_tree: &TaskTypeTree,
    node_id: &str,
    axis: DecisionAxis,
    donor: Option<&TaskTypeTree>,
) -> Option<String> {
    donor
        .and_then(|donor| {
            let weight = donor_weight(project_tree, node_id, donor)?;
            let (own, theirs) = (project_tree.nodes.get(node_id)?, donor.nodes.get(node_id)?);
            blended_winner(own, theirs, weight, axis)
        })
        .or_else(|| {
            project_tree
                .effective_winner(node_id, axis)
                .map(str::to_owned)
        })
}

/// The weight `donor`'s evidence carries on `node_id`'s reads in
/// `project_tree`: `q = W * max(0, 1 - r / THIN_LEAF_MIN_RECEIPTS)`, with
/// `r` the project leaf's own stored receipts, wherever `matched` lends
/// (the thin live leaf of a project's own tree on the donor's exact live
/// path); `None` where nothing is lent. The Coach's winner reads and the
/// live planner's measured reads take their weight here alone.
#[must_use]
pub(crate) fn donor_weight(
    project_tree: &TaskTypeTree,
    node_id: &str,
    donor: &TaskTypeTree,
) -> Option<f64> {
    let (own, _, _) = matched(project_tree, node_id, donor)?;
    let fade = (1.0 - own.receipt_count as f64 / THIN_LEAF_MIN_RECEIPTS as f64).max(0.0);
    Some(PROJECT_TREE_DONOR_WEIGHT * fade)
}

/// The path, root first, on which `node_id`'s reads in `project_tree` blend
/// `donor`'s counts; `None` where they do not.
pub(super) fn donor_path(
    project_tree: &TaskTypeTree,
    node_id: &str,
    donor: &TaskTypeTree,
) -> Option<Vec<String>> {
    matched(project_tree, node_id, donor)
        .map(|(_, _, path)| path.into_iter().map(str::to_owned).collect())
}

/// The project's thin live leaf `node_id`, the donor's live leaf on exactly
/// its path, and that path's node ids, root first. `None` unless
/// `project_tree` is a project's own tree.
fn matched<'a, 'b>(
    project_tree: &'a TaskTypeTree,
    node_id: &str,
    donor: &'b TaskTypeTree,
) -> Option<(&'a TaskTypeNode, &'b TaskTypeNode, Vec<&'a str>)> {
    if !matches!(project_tree.scope, TreeScope::Project { .. }) {
        return None;
    }
    let own = project_tree
        .nodes
        .get(node_id)
        .filter(|node| node.is_live() && node.is_thin() && project_tree.is_leaf(node_id))?;
    let theirs = donor
        .nodes
        .get(node_id)
        .filter(|node| node.is_live() && donor.is_leaf(node_id))?;
    let (mut mine, mut other) = (own, theirs);
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(mine.node_id.as_str())
            || mine.node_id != other.node_id
            || mine.split_axis != other.split_axis
            || mine.split_winner != other.split_winner
            || !mine.is_live()
            || !other.is_live()
        {
            return None;
        }
        path.push(mine.node_id.as_str());
        match (mine.parent.as_deref(), other.parent.as_deref()) {
            (None, None) => break,
            (Some(up), Some(their_up)) if up == their_up => {
                mine = project_tree.nodes.get(up)?;
                other = donor.nodes.get(their_up)?;
            }
            _ => return None,
        }
    }
    path.reverse();
    Some((own, theirs, path))
}

/// The strict leader of `own`'s counts on `axis` plus `weight` times
/// `donor`'s ([`donor_weight`]), when it carries at least
/// [`SPLIT_MIN_RUNS_PER_WINNER`] weighted runs.
fn blended_winner(
    own: &TaskTypeNode,
    donor: &TaskTypeNode,
    weight: f64,
    axis: DecisionAxis,
) -> Option<String> {
    let mut mass: BTreeMap<&str, f64> = BTreeMap::new();
    for (node, scale) in [(own, 1.0), (donor, weight)] {
        for (winner, runs) in node.decision_wins.get(axis.as_str()).into_iter().flatten() {
            *mass.entry(winner.as_str()).or_default() += scale * *runs as f64;
        }
    }
    let mut best: Option<(&str, f64)> = None;
    let mut tied = false;
    for (winner, runs) in mass {
        match best.map(|(_, top)| runs.total_cmp(&top)) {
            Some(Ordering::Less) => {}
            Some(Ordering::Equal) => tied = true,
            _ => {
                best = Some((winner, runs));
                tied = false;
            }
        }
    }
    let (winner, runs) = best.filter(|_| !tied)?;
    runs.total_cmp(&(SPLIT_MIN_RUNS_PER_WINNER as f64))
        .is_ge()
        .then(|| winner.to_owned())
}
