//! Typed Context Board render projections.

mod agents;
mod frame;
mod plugin;
mod stream;

pub use stream::{
    AppliedStreamState, BoardEvent, BoardRenderMode, BoardSnapshot, BoardStreamFrame,
    BoardStreamRegistry, CarrierCoalesceBuffer, CoalesceOutcome, DeliveryClass, DeliveryPolicy,
    DeltaRow, FrameApplyOutcome, FrameEnqueueOutcome, FrameKind, RouteObservation,
    StreamConnectionId, StreamConnectionState, SubscriptionError, SubscriptionReceipt,
    SubscriptionScope, WakeEnvelope,
};
pub(crate) use stream::{
    ChildMintError, ChildProvenanceSource, OwnTaskProvenanceSource, WakeMintError,
    mint_child_event, mint_own_task_event,
};
mod tasks;

pub use agents::{
    AgentLane, AgentRow, AgentsSection, ChildAgentPresence, PeerPresence, render_agents_section,
};
pub use frame::{
    BoardBlockHeader, BoardBudget, BoardBudgetRequest, BoardBudgetSource, BoardFrame,
    BoardFrameError, BoardLegend, BoardRender, BoardRenderMetadata, BoardSection, BudgetPolicyRef,
    CANONICAL_BOARD_LEGEND, CORE_SHED_ORDER, MAX_BOARD_ROW_BYTES, PLUGIN_SECTION_BUDGET_POLICY_REF,
    SHED_ORDER, SectionPolicy, SectionView, ShedOutcome, ShedRank, ShedSection,
    assemble_task_agent_sections, render_board_block, resolve_board_budget,
    section_policy_for_budget_ref, shed,
};
pub use tasks::{
    JobPresence, TaskBoardStatus, TaskIntentPresence, TaskRow, TasksSection, expand_task,
    failed_lane, fold_up_status, render_tasks_section,
};
pub(crate) use tasks::{ack_task_in_txn, cancel_task_in_txn, task_is_acked, task_is_cancelled};

/// Collapse control characters so a rendered row is always one physical line.
pub(super) fn one_line_token(s: &str) -> String {
    s.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod test_support {
    use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
    use crate::run_tree::{RunTreeNode, RunTreeStatus, RunTreeTimestamps};

    pub(super) fn run_tree_node(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
    ) -> RunTreeNode {
        run_tree_node_with_worker_kind(attempt_id, agent_id, status, AGENT_DISPATCH_ATTEMPT_TYPE)
    }

    pub(super) fn run_tree_node_with_worker_kind(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
        worker_kind: &str,
    ) -> RunTreeNode {
        RunTreeNode {
            attempt_id: attempt_id.to_owned(),
            run_id: None,
            parent_id: None,
            worker_kind: worker_kind.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            status,
            timestamps: RunTreeTimestamps {
                created_at: 1,
                updated_at: 2,
            },
            failure: None,
            events: Vec::new(),
            children: Vec::new(),
        }
    }
}
