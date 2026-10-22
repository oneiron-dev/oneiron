//! A stored task-type tree's structure (FIX 9566), checked on store and on
//! load: the root has no parent, every other node's parent chain ends at the
//! root, and every merge chain ends at a live stored node. A self link, a
//! cycle or a missing target is refused, found with visited sets however many
//! nodes the tree holds; no node count bounds it.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::task_type::{ROOT_NODE_ID, TaskTypeTree};

use super::super::widen_record::invalid;

/// A tree is structurally whole: a version, a parentless root, every node
/// keyed by its own id and its parents a stored chain ending at the root, and
/// every merge a stored chain ending at a live node.
pub(super) fn validate_tree(tree: &TaskTypeTree) -> Result<()> {
    if tree.version == 0 {
        return Err(invalid("a type tree version starts at 1"));
    }
    let Some(root) = tree.nodes.get(ROOT_NODE_ID) else {
        return Err(invalid("a type tree has a root"));
    };
    if root.parent.is_some() {
        return Err(invalid("a type tree's root has no parent"));
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
    // Nodes whose parent chain is known to end at the root.
    let mut rooted: BTreeSet<&str> = BTreeSet::from([ROOT_NODE_ID]);
    // Nodes whose merge chain is known to end at a live node.
    let mut merged: BTreeSet<&str> = BTreeSet::new();
    for id in tree.nodes.keys() {
        parent_chain_ends_at_root(tree, id, &mut rooted)?;
        merge_chain_ends_live(tree, id, &mut merged)?;
    }
    Ok(())
}

/// Walks `id`'s parents to the root, or to a node already known to reach it,
/// adding every node passed to `rooted`.
fn parent_chain_ends_at_root<'a>(
    tree: &'a TaskTypeTree,
    id: &'a str,
    rooted: &mut BTreeSet<&'a str>,
) -> Result<()> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = id;
    while !rooted.contains(cursor) {
        if !seen.insert(cursor) {
            return Err(invalid("a type node's parent chain comes back on itself"));
        }
        path.push(cursor);
        let parent = tree
            .nodes
            .get(cursor)
            .and_then(|node| node.parent.as_deref())
            .ok_or_else(|| invalid("every type node's parent chain ends at the root"))?;
        cursor = parent;
    }
    rooted.extend(path);
    Ok(())
}

/// Walks `id`'s merges to a live stored node, or to a node already known to
/// reach one, adding every node passed to `merged`.
fn merge_chain_ends_live<'a>(
    tree: &'a TaskTypeTree,
    id: &'a str,
    merged: &mut BTreeSet<&'a str>,
) -> Result<()> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = id;
    while !merged.contains(cursor) {
        if !seen.insert(cursor) {
            return Err(invalid("a type node's merge chain comes back on itself"));
        }
        path.push(cursor);
        let node = tree
            .nodes
            .get(cursor)
            .ok_or_else(|| invalid("a type node merges into a stored node"))?;
        match node.merged_into.as_deref() {
            Some(target) => cursor = target,
            None => break,
        }
    }
    merged.extend(path);
    Ok(())
}
