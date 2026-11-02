//! A type's split (ARCH-0079 #task-type): one child per winner its tasks
//! disagree on.
//!
//! Each new child takes a fresh id (FIX 2971): a digest of its parent, its
//! axis, its exact winner and its generation, the count of nodes split from
//! that parent on that axis for that exact winner before it. The parent segment
//! is the first 16 hex of the framed parent digest (FIX 9053), so depth no longer
//! lengthens the id. A node whose earlier children merged away splits again into
//! new children beside the tombstones its old receipts resolve through, and two
//! trees that split the same way spell the same child alike, as the vault's donor
//! prior and the merge-back read a leaf by its id.

use super::{
    DecisionAxis, SPLIT_MIN_RUNS_PER_WINNER, SplitDecision, TaskTypeNode, TaskTypeRef,
    TaskTypeTree, invalid_type_ref,
};
use crate::error::Result;

/// The digest domain of a split child's id.
const SPLIT_CHILD_ID_DOMAIN: &[u8] = b"oneiron.task_type.split_child.v1";

impl TaskTypeTree {
    /// Splits one node on a decision its tasks disagree on: one child per
    /// qualifying winner. Bumps the tree version. Refused when the node
    /// does not actually disagree on `axis` — splits follow decisions,
    /// never topic, so there is no split-by-name path. A winner that has a
    /// live child under the node keeps it; one whose children all merged
    /// away gets a fresh child, and its tombstones stay as they are.
    pub fn split(&mut self, node_id: &str, axis: DecisionAxis) -> Result<Vec<TaskTypeRef>> {
        let winners: Vec<String> = {
            let node = self
                .nodes
                .get(node_id)
                .ok_or_else(|| invalid_type_ref("split node is outside the tree"))?;
            if !node.is_live() {
                return Err(invalid_type_ref("split node has merged away"));
            }
            if !node.disagrees_on(axis) {
                return Err(invalid_type_ref(
                    "a type splits only when its tasks disagree on a decision",
                ));
            }
            node.decision_wins
                .get(axis.as_str())
                .map(|by_winner| {
                    by_winner
                        .iter()
                        .filter(|(_, runs)| **runs >= SPLIT_MIN_RUNS_PER_WINNER)
                        .map(|(winner, _)| winner.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut created = Vec::new();
        for winner in winners {
            let mut generation = 0_u64;
            let mut live = false;
            for node in self.nodes.values().filter(|node| {
                node.parent.as_deref() == Some(node_id)
                    && node.split_axis == Some(axis)
                    && node.split_winner.as_deref() == Some(winner.as_str())
            }) {
                generation = generation.saturating_add(1);
                live |= node.is_live();
            }
            let child_id = split_child_id(node_id, axis, &winner, generation);
            if live || self.nodes.contains_key(&child_id) {
                continue;
            }
            let mut child = TaskTypeNode::new(
                &child_id,
                Some(node_id),
                &format!("{node_id} where {} is {winner}", axis.as_str()),
                None,
            );
            child.split_axis = Some(axis);
            child.split_winner = Some(winner);
            self.nodes.insert(child_id.clone(), child);
            created.push(child_id);
        }
        if created.is_empty() {
            return Err(invalid_type_ref("split produced no new child type"));
        }
        self.version = self.version.saturating_add(1);
        Ok(created
            .iter()
            .map(|child_id| self.type_ref(child_id))
            .collect())
    }
}

/// A split child's id, `<parent-hash>/<decision>.<digest>` (FIX 9053): the parent
/// segment is the first 16 hex of BLAKE3 over the framed parent, and the digest
/// is the first 16 hex of BLAKE3 over the framed parent, axis, exact winner and
/// generation, so depth no longer lengthens the id. Only characters a typeRef
/// node id may hold, and no lossy spelling of the winner: two winners one slug
/// would fold stay two children.
fn split_child_id(parent: &str, axis: DecisionAxis, winner: &str, generation: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SPLIT_CHILD_ID_DOMAIN);
    for part in [
        parent.as_bytes(),
        axis.as_str().as_bytes(),
        winner.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.update(&generation.to_le_bytes());
    let digest = hasher.finalize().to_hex();
    let mut parent_hasher = blake3::Hasher::new();
    parent_hasher.update(SPLIT_CHILD_ID_DOMAIN);
    parent_hasher.update(&(parent.as_bytes().len() as u64).to_le_bytes());
    parent_hasher.update(parent.as_bytes());
    let parent_digest = parent_hasher.finalize().to_hex();
    let parent_hash = &parent_digest.as_str()[..16];
    format!(
        "{parent_hash}/{}.{}",
        SplitDecision::from(axis).as_str(),
        &digest.as_str()[..16]
    )
}
