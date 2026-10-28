//! Promotion's equivalence (FIX 9052): a fork's split child and an upstream
//! child split from the same parent on the same axis for the same exact
//! winner are one type, whatever generation each tree's own split history
//! gave its id. Promoting the leaf names the upstream child; it never adds
//! a second live child for that split.

use super::{TaskTypeNode, TaskTypeTree};

impl TaskTypeTree {
    /// The id of this tree's live child that `leaf`, another tree's split
    /// child, is the same split as: the same parent, split axis and exact
    /// winner. `None` for a leaf no split made, or where no such child lives.
    pub(super) fn live_split_twin(&self, leaf: &TaskTypeNode) -> Option<String> {
        let parent = leaf.parent.as_deref()?;
        let axis = leaf.split_axis?;
        let winner = leaf.split_winner.as_deref()?;
        self.nodes
            .values()
            .find(|node| {
                node.is_live()
                    && node.parent.as_deref() == Some(parent)
                    && node.split_axis == Some(axis)
                    && node.split_winner.as_deref() == Some(winner)
            })
            .map(|node| node.node_id.clone())
    }
}
