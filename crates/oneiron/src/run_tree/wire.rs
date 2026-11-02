//! The run tree's conversions to and from its flat wire table (FIX 10603).
//! Entry: `RunTreeWire::from`, `RunTree::try_from`.
//!
//! Both walk a heap stack, never the call stack, so a tree as deep as its
//! run's parent chain is written and read whole: no depth or count limits
//! it. Writing numbers the nodes in pre-order; reading takes any table whose
//! roots and children name every node exactly once, and refuses one that
//! names a node twice, names none past the table's end, or leaves a node
//! unnamed.

use std::fmt;

use super::types::{RunTree, RunTreeNode, RunTreeWire, RunTreeWireNode};

/// Why a [`RunTreeWire`] table does not read as a tree: its roots and
/// children do not name each of its nodes exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunTreeWireError;

impl fmt::Display for RunTreeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run tree table does not name each of its nodes exactly once")
    }
}

impl std::error::Error for RunTreeWireError {}

impl From<RunTree> for RunTreeWire {
    fn from(tree: RunTree) -> Self {
        let RunTree { roots, repairs } = tree;
        let mut nodes: Vec<RunTreeWireNode> = Vec::new();
        let mut root_indexes = Vec::with_capacity(roots.len());
        // Pre-order: a node takes the next index and joins its parent's
        // children, then its own children wait first in line, in order.
        let mut pending: Vec<(RunTreeNode, Option<usize>)> =
            roots.into_iter().rev().map(|node| (node, None)).collect();
        while let Some((mut node, parent)) = pending.pop() {
            let index = nodes.len();
            let named = wire_index(index);
            match parent.and_then(|parent| nodes.get_mut(parent)) {
                Some(parent) => parent.children.push(named),
                None => root_indexes.push(named),
            }
            let children = std::mem::take(&mut node.children);
            nodes.push(wire_node(&mut node));
            pending.extend(children.into_iter().rev().map(|child| (child, Some(index))));
        }
        Self {
            nodes,
            roots: root_indexes,
            repairs,
        }
    }
}

impl TryFrom<RunTreeWire> for RunTree {
    type Error = RunTreeWireError;

    fn try_from(wire: RunTreeWire) -> Result<Self, Self::Error> {
        let RunTreeWire {
            nodes,
            roots,
            repairs,
        } = wire;
        let count = nodes.len();
        let mut built: Vec<Option<RunTreeNode>> = Vec::with_capacity(count);
        let mut children_of: Vec<Vec<usize>> = Vec::with_capacity(count);
        for node in nodes {
            let (node, children) = tree_node(node);
            children_of.push(
                children
                    .into_iter()
                    .map(table_index)
                    .collect::<Result<_, _>>()?,
            );
            built.push(Some(node));
        }
        let roots: Vec<usize> = roots
            .into_iter()
            .map(table_index)
            .collect::<Result<_, _>>()?;
        // Pre-order from the roots: a node named twice, or past the end, is
        // no tree, and neither is a table with a node left unnamed.
        let mut seen = vec![false; count];
        let mut order = Vec::with_capacity(count);
        let mut pending: Vec<usize> = roots.iter().rev().copied().collect();
        while let Some(at) = pending.pop() {
            let named = seen.get_mut(at).ok_or(RunTreeWireError)?;
            if std::mem::replace(named, true) {
                return Err(RunTreeWireError);
            }
            order.push(at);
            if let Some(children) = children_of.get(at) {
                pending.extend(children.iter().rev().copied());
            }
        }
        if order.len() != count {
            return Err(RunTreeWireError);
        }
        // In reverse pre-order every node's children are whole before it.
        for &at in order.iter().rev() {
            let children = children_of.get(at).map_or(&[][..], Vec::as_slice);
            let mut whole = Vec::with_capacity(children.len());
            for &child in children {
                whole.push(
                    built
                        .get_mut(child)
                        .and_then(Option::take)
                        .ok_or(RunTreeWireError)?,
                );
            }
            if let Some(Some(node)) = built.get_mut(at) {
                node.children = whole;
            }
        }
        let roots = roots
            .into_iter()
            .map(|at| {
                built
                    .get_mut(at)
                    .and_then(Option::take)
                    .ok_or(RunTreeWireError)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { roots, repairs })
    }
}

/// `index` as a table index. A table index is a `u64` on the wire.
fn wire_index(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}

/// A wire index as an index into the table, refused when this machine
/// cannot address it.
fn table_index(index: u64) -> Result<usize, RunTreeWireError> {
    usize::try_from(index).map_err(|_| RunTreeWireError)
}

/// `node`'s own fields, taken out of it, with no children yet.
fn wire_node(node: &mut RunTreeNode) -> RunTreeWireNode {
    RunTreeWireNode {
        attempt_id: std::mem::take(&mut node.attempt_id),
        run_id: node.run_id.take(),
        parent_id: node.parent_id.take(),
        worker_kind: std::mem::take(&mut node.worker_kind),
        worker: node.worker.take(),
        agent_id: node.agent_id.take(),
        status: node.status,
        result_ref: node.result_ref.take(),
        timestamps: node.timestamps,
        failure: node.failure.take(),
        events: std::mem::take(&mut node.events),
        children: Vec::new(),
    }
}

/// `node` as a tree node with no children yet, and the indexes of the
/// children it names.
fn tree_node(node: RunTreeWireNode) -> (RunTreeNode, Vec<u64>) {
    let RunTreeWireNode {
        attempt_id,
        run_id,
        parent_id,
        worker_kind,
        worker,
        agent_id,
        status,
        result_ref,
        timestamps,
        failure,
        events,
        children,
    } = node;
    (
        RunTreeNode {
            attempt_id,
            run_id,
            parent_id,
            worker_kind,
            worker,
            agent_id,
            status,
            result_ref,
            timestamps,
            failure,
            events,
            children: Vec::new(),
        },
        children,
    )
}
