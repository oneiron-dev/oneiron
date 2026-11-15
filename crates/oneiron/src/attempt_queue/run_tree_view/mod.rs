//! Run-tree view types: nodes, status/event vocab, repairs, and markers.

use serde::{Deserialize, Serialize};

mod wire;
pub use wire::RunTreeWireError;

/// Renderable run tree for dashboard/read APIs. It is written and read as
/// its flat [`RunTreeWire`] table (FIX 10603).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "RunTreeWire", try_from = "RunTreeWire")]
pub struct RunTree {
    pub roots: Vec<RunTreeNode>,
    pub repairs: Vec<RunTreeRepair>,
    pub deletions: Vec<RunTreeDeletion>,
}

#[doc(hidden)]
pub use oneiron_records::attempt_queue::run_tree_view::{
    RunTreeDeletion, RunTreeEvent, RunTreeEventKind, RunTreeFailure, RunTreeNodeMarker,
    RunTreeNodeMarkerKind, RunTreeRepair, RunTreeStatus, RunTreeTimestamps, RunTreeWireNode,
};

/// One renderable attempt node.
///
/// A persisted tree can be as deep as its run's parent chain, so dropping,
/// cloning, comparing and debug-printing a node walk its subtree on a heap
/// stack, never the call stack (FIX 10067); so do writing and reading its
/// tree, as the flat [`RunTreeWire`] table (FIX 10603).
pub struct RunTreeNode {
    pub attempt_id: String,
    pub run_id: Option<String>,
    pub parent_id: Option<String>,
    pub worker_kind: String,
    /// Operator-selected worker, if this attempt has been redirected.
    pub worker: Option<String>,
    /// The dispatched agent's label for `agent.dispatch` attempts (decoded from
    /// the payload snapshot; tolerant — a malformed inner input renders as
    /// `None`).
    pub agent_id: Option<String>,
    pub status: RunTreeStatus,
    /// The artifact version this attempt's durable output lives in, copied
    /// from the backing queue row. Cross-executor: any executor kind that
    /// named a result projects it here, not only foreign ones.
    pub result_ref: Option<String>,
    pub timestamps: RunTreeTimestamps,
    pub failure: Option<RunTreeFailure>,
    pub events: Vec<RunTreeEvent>,
    pub children: Vec<RunTreeNode>,
}

/// A run tree as it is written and read (FIX 10603): every node once, in
/// pre-order, each naming its children by index, so a tree of any depth is
/// written and read on a heap stack. The roots and each node's children
/// keep their order; a table that is not one forest of its nodes does not
/// read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeWire {
    pub nodes: Vec<RunTreeWireNode>,
    /// The roots, as indexes into `nodes`, in order.
    pub roots: Vec<u64>,
    pub repairs: Vec<RunTreeRepair>,
    pub deletions: Vec<RunTreeDeletion>,
}

impl RunTreeNode {
    /// This node alone: every field but its children, which stay empty.
    fn shallow_clone(&self) -> Self {
        Self {
            attempt_id: self.attempt_id.clone(),
            run_id: self.run_id.clone(),
            parent_id: self.parent_id.clone(),
            worker_kind: self.worker_kind.clone(),
            worker: self.worker.clone(),
            agent_id: self.agent_id.clone(),
            status: self.status,
            result_ref: self.result_ref.clone(),
            timestamps: self.timestamps,
            failure: self.failure.clone(),
            events: self.events.clone(),
            children: Vec::new(),
        }
    }

    /// Whether this node's own fields, its children aside, equal `other`'s.
    fn same_fields(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.run_id == other.run_id
            && self.parent_id == other.parent_id
            && self.worker_kind == other.worker_kind
            && self.worker == other.worker
            && self.agent_id == other.agent_id
            && self.status == other.status
            && self.result_ref == other.result_ref
            && self.timestamps == other.timestamps
            && self.failure == other.failure
            && self.events == other.events
    }
}

impl Drop for RunTreeNode {
    /// Drains the subtree onto a heap stack, so no node's drop recurses.
    fn drop(&mut self) {
        let mut pending = std::mem::take(&mut self.children);
        while let Some(mut node) = pending.pop() {
            pending.append(&mut node.children);
        }
    }
}

impl Clone for RunTreeNode {
    fn clone(&self) -> Self {
        // Breadth-first, so every node's index is past its parent's.
        let mut order: Vec<(&Self, Option<usize>)> = vec![(self, None)];
        let mut next = 0;
        while let Some(&(node, _)) = order.get(next) {
            order.extend(node.children.iter().map(|child| (child, Some(next))));
            next += 1;
        }
        let mut built: Vec<Option<Self>> = order
            .iter()
            .map(|(node, _)| Some(node.shallow_clone()))
            .collect();
        // From the last index back: a node is whole once its children, all
        // at later indexes, are attached. They arrive in reverse order.
        for index in (1..order.len()).rev() {
            let child = built.get_mut(index).and_then(Option::take);
            let parent = order.get(index).and_then(|(_, parent)| *parent);
            if let (Some(mut child), Some(parent)) = (child, parent) {
                child.children.reverse();
                if let Some(Some(parent)) = built.get_mut(parent) {
                    parent.children.push(child);
                }
            }
        }
        let mut root = built
            .first_mut()
            .and_then(Option::take)
            .unwrap_or_else(|| self.shallow_clone());
        root.children.reverse();
        root
    }
}

impl PartialEq for RunTreeNode {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            if !left.same_fields(right) || left.children.len() != right.children.len() {
                return false;
            }
            pending.extend(left.children.iter().zip(&right.children));
        }
        true
    }
}

impl Eq for RunTreeNode {}

impl std::fmt::Debug for RunTreeNode {
    /// The subtree in pre-order, one entry per node with its depth, read on
    /// a heap stack.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = formatter.debug_list();
        let mut pending = vec![(0_usize, self)];
        while let Some((depth, node)) = pending.pop() {
            list.entry(&NodeFields { depth, node });
            pending.extend(node.children.iter().rev().map(|child| (depth + 1, child)));
        }
        list.finish()
    }
}

/// One node's own fields for [`RunTreeNode`]'s debug output.
struct NodeFields<'a> {
    depth: usize,
    node: &'a RunTreeNode,
}

impl std::fmt::Debug for NodeFields<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let node = self.node;
        formatter
            .debug_struct("RunTreeNode")
            .field("depth", &self.depth)
            .field("attempt_id", &node.attempt_id)
            .field("run_id", &node.run_id)
            .field("parent_id", &node.parent_id)
            .field("worker_kind", &node.worker_kind)
            .field("worker", &node.worker)
            .field("agent_id", &node.agent_id)
            .field("status", &node.status)
            .field("result_ref", &node.result_ref)
            .field("timestamps", &node.timestamps)
            .field("failure", &node.failure)
            .field("events", &node.events)
            .field("children", &node.children.len())
            .finish()
    }
}

/// An unchanged run tree plus the marker naming its failing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeFailureDiagram {
    pub tree: RunTree,
    pub marker: RunTreeNodeMarker,
}
