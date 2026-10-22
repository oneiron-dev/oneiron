//! The engine run tree's projection onto the core run-tree DTOs, one node
//! at a time (FIX 10067): a node is projected flat, its fields taken, and its
//! children are written by [`super::encode`], so no projection recurses.

use std::mem;

use super::{
    CoreRunTreeEvent, CoreRunTreeEventKind, CoreRunTreeFailure, CoreRunTreeNode, CoreRunTreeRepair,
    CoreRunTreeResponse, CoreRunTreeStatus, CoreRunTreeTimestamps,
};

/// The response with its repairs and no roots: [`super::encode`] writes the
/// roots into it.
pub(super) fn core_run_tree_shell(repairs: Vec<oneiron::RunTreeRepair>) -> CoreRunTreeResponse {
    CoreRunTreeResponse {
        roots: Vec::new(),
        repairs: repairs.into_iter().map(core_run_tree_repair).collect(),
    }
}

/// `node` alone, its fields taken, with no children: [`super::encode`]
/// writes them into its `children`.
pub(super) fn core_run_tree_node(node: &mut oneiron::RunTreeNode) -> CoreRunTreeNode {
    CoreRunTreeNode {
        attempt_id: mem::take(&mut node.attempt_id),
        run_id: node.run_id.take(),
        parent_id: node.parent_id.take(),
        worker_kind: mem::take(&mut node.worker_kind),
        worker: node.worker.take(),
        agent_id: node.agent_id.take(),
        status: core_run_tree_status(node.status),
        result_ref: node.result_ref.take(),
        timestamps: CoreRunTreeTimestamps {
            created_at: node.timestamps.created_at,
            updated_at: node.timestamps.updated_at,
        },
        failure: node.failure.take().map(|failure| CoreRunTreeFailure {
            reason: failure.reason,
        }),
        events: mem::take(&mut node.events)
            .into_iter()
            .map(core_run_tree_event)
            .collect(),
        children: Vec::new(),
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
