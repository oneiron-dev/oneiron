//! The engine run tree's projection onto the core run-tree DTOs (FIX
//! 11107): the flat table the SDK reads ([`oneiron::run_tree::RunTreeWire`]),
//! every node once, in pre-order, with the roots and each node's children
//! named by index. The table is numbered on a heap stack and each node is
//! projected alone, so no projection recurses, however deep the tree.

use oneiron::run_tree::{RunTreeWire, RunTreeWireNode};

use super::{
    CoreRunTreeEvent, CoreRunTreeEventKind, CoreRunTreeFailure, CoreRunTreeNode, CoreRunTreeRepair,
    CoreRunTreeResponse, CoreRunTreeStatus, CoreRunTreeTimestamps,
};

/// `tree` as the core run-tree response: its flat table, with every node,
/// repair and order it has.
pub(super) fn core_run_tree(tree: oneiron::RunTree) -> CoreRunTreeResponse {
    let RunTreeWire {
        nodes,
        roots,
        repairs,
    } = RunTreeWire::from(tree);
    CoreRunTreeResponse {
        nodes: nodes.into_iter().map(core_run_tree_node).collect(),
        roots,
        repairs: repairs.into_iter().map(core_run_tree_repair).collect(),
    }
}

/// One node of the table, its children named by index.
fn core_run_tree_node(node: RunTreeWireNode) -> CoreRunTreeNode {
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
    CoreRunTreeNode {
        attempt_id,
        run_id,
        parent_id,
        worker_kind,
        worker,
        agent_id,
        status: core_run_tree_status(status),
        result_ref,
        timestamps: CoreRunTreeTimestamps {
            created_at: timestamps.created_at,
            updated_at: timestamps.updated_at,
        },
        failure: failure.map(|failure| CoreRunTreeFailure {
            reason: failure.reason,
        }),
        events: events.into_iter().map(core_run_tree_event).collect(),
        children,
    }
}

fn core_run_tree_status(status: oneiron::RunTreeStatus) -> CoreRunTreeStatus {
    match status {
        oneiron::RunTreeStatus::Queued => CoreRunTreeStatus::Queued,
        oneiron::RunTreeStatus::Running => CoreRunTreeStatus::Running,
        oneiron::RunTreeStatus::Paused => CoreRunTreeStatus::Paused,
        oneiron::RunTreeStatus::Completed => CoreRunTreeStatus::Completed,
        oneiron::RunTreeStatus::Failed => CoreRunTreeStatus::Failed,
        oneiron::RunTreeStatus::Cancelled => CoreRunTreeStatus::Cancelled,
        oneiron::RunTreeStatus::Abandoned => CoreRunTreeStatus::Abandoned,
    }
}

fn core_run_tree_event(event: oneiron::RunTreeEvent) -> CoreRunTreeEvent {
    CoreRunTreeEvent {
        sequence: event.sequence,
        at: event.at,
        actor: event.actor,
        kind: core_run_tree_event_kind(event.kind),
        note: event.note,
    }
}

fn core_run_tree_event_kind(kind: oneiron::RunTreeEventKind) -> CoreRunTreeEventKind {
    match kind {
        oneiron::RunTreeEventKind::Created => CoreRunTreeEventKind::Created,
        oneiron::RunTreeEventKind::Claimed => CoreRunTreeEventKind::Claimed,
        oneiron::RunTreeEventKind::Paused => CoreRunTreeEventKind::Paused,
        oneiron::RunTreeEventKind::Resumed => CoreRunTreeEventKind::Resumed,
        oneiron::RunTreeEventKind::Completed => CoreRunTreeEventKind::Completed,
        oneiron::RunTreeEventKind::Failed => CoreRunTreeEventKind::Failed,
        oneiron::RunTreeEventKind::Cancelled => CoreRunTreeEventKind::Cancelled,
        oneiron::RunTreeEventKind::Interrupted => CoreRunTreeEventKind::Interrupted,
        oneiron::RunTreeEventKind::Abandoned => CoreRunTreeEventKind::Abandoned,
        oneiron::RunTreeEventKind::ResultAttached => CoreRunTreeEventKind::ResultAttached,
        oneiron::RunTreeEventKind::Redirected => CoreRunTreeEventKind::Redirected,
    }
}

fn core_run_tree_repair(repair: oneiron::RunTreeRepair) -> CoreRunTreeRepair {
    match repair {
        oneiron::RunTreeRepair::MissingParent {
            attempt_id,
            missing_parent_id,
        } => CoreRunTreeRepair::MissingParent {
            attempt_id,
            missing_parent_id,
        },
        oneiron::RunTreeRepair::ParentCycle {
            attempt_id,
            parent_id,
        } => CoreRunTreeRepair::ParentCycle {
            attempt_id,
            parent_id,
        },
    }
}
