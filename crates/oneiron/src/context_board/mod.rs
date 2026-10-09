//! Typed Context Board render projections.
//!
//! WORLDS, MEMORIES, TASKS, AGENTS, SKILLS, session read-set riders and stream projections.

mod agents;
mod agents_fanout;
pub(crate) use agents_fanout::fanout_agent_rows;
mod capabilities;
mod observations;
#[cfg(test)]
mod observations_tests;
mod own_changes;
mod read_set;
mod room;
mod room_verbs;
#[cfg(test)]
mod room_verbs_tests;
mod worlds;
pub use capabilities::{CapabilityHit, SkillsSection};
pub use read_set::{
    ChangedDelivery, ChangedEvent, ChangedLine, ConnectorChange, ConnectorMount, ProposalChange,
    ProposalReason, ServedLifecycle, SessionReadSet,
};
pub use room::{RoomBar, RoomMode, RoomPosture, RoomPresence, RoomSection, room_scope};
pub use worlds::{WorldPresence, WorldsSection};
mod frame;
mod history;
mod hydration;
mod self_brief;
pub(crate) use history::validate_board_claim;
pub use history::{
    BoardHistoryError, BoardSelection, BoardTurn, BoardTurnReceipt, ReconstructedBoard,
};
pub use self_brief::{
    BriefPlacement, BriefSkillRow, ClassLimit, ClassVerdict, CommunicationLimits, PlacedSelfBrief,
    SelfBrief, SelfBriefInput, SelfBriefSession, SelfBriefState,
};
mod memories;
mod memories_frame;
mod memories_projection;
mod memory_pins;
mod notifications;
pub use memories::MemoryTier;
pub use memories_frame::assemble_memories_sections;
mod plugin;
mod stream;

pub use stream::{
    AppliedStreamState, BoardEvent, BoardRenderMode, BoardSnapshot, BoardStreamFrame,
    BoardStreamRegistry, CarrierCoalesceBuffer, CoalesceOutcome, DeliveryClass, DeliveryPolicy,
    DeltaRow, FrameApplyOutcome, FrameEnqueueOutcome, FrameKind, RouteObservation,
    StreamConnectionId, StreamConnectionState, SubscriptionError, SubscriptionReceipt,
    SubscriptionScope, WakeEnvelope,
};
pub use stream::{
    BindInstanceError, HarnessInstanceKey, InstanceBindingReceipt, WakeAdapterKind,
    WakeDeliveryOutcome, WakeDeliveryReportError, WakeDispatch, WakeDispatchObservations,
    WakeReportDisposition,
};
#[cfg(test)]
mod surfaces_tests;
mod tasks;

pub use agents::{
    AgentLane, AgentRow, AgentsSection, ChildAgentPresence, PeerPresence, render_agents_section,
};
pub use frame::{
    BoardBlockHeader, BoardBudget, BoardBudgetRequest, BoardBudgetSource, BoardFrame,
    BoardFrameError, BoardLegend, BoardRender, BoardRenderMetadata, BoardSection, BudgetPolicyRef,
    CANONICAL_BOARD_LEGEND, CORE_SHED_ORDER, MAX_BOARD_ROW_BYTES, PLUGIN_SECTION_BUDGET_POLICY_REF,
    SHED_ORDER, SectionPolicy, SectionView, ShedOutcome, ShedRank, ShedSection,
    TASK_LABEL_MAX_BYTES, TASK_ROW_FIXED_TOKEN_BYTES, assemble_task_agent_sections,
    render_board_block, resolve_board_budget, section_policy_for_budget_ref, shed,
};
pub use hydration::{
    AssembledContext, HydrationBudget, NotificationItem, SessionContext, UnprocessedItem,
};
pub use memories::{
    CompanionAssembly, MEMORIES_SECTION_VERSION_V4, MemoriesBudget, MemoriesCursor,
    MemoriesSection, MemoryRow, MemorySlot, MemorySource,
};
pub use memories_projection::project_memories_section;
pub(crate) use notifications::{NotificationRecipientScope, notification_recipient_scope};
pub use notifications::{
    caller_marker_contains, notification_body_json, notification_scoped_to_caller,
};
pub use plugin::{
    AdmittedPluginSection, AuthorityLaneRef, BoardBlockKind, BoardBlockRecord, BoardBlockScope,
    BoardBlockWriteEnvelope, CORE_SECTION_IDS, PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION,
    PLUGIN_PROPOSALS_SECTION_NAME, PREDICATE_PLUGIN_SECTION_INSTALL, PackSectionRegistration,
    PluginInstallClaimPayload, PluginInstallExecutor, PluginInstallOrigin, PluginInstallSource,
    PluginInstallTarget, PluginProposalRow, PluginResult, PluginSectionAdmission,
    PluginSectionError, PluginSectionInstallProposal, PluginSectionRegistry, PluginSectionRow,
    PluginSectionSnapshot, PluginSuggestionKey, SECTION_MANIFEST_SCHEMA_VERSION,
    SectionBindingResolver, SectionId, SectionManifest, SectionManifestEnvelope,
    SectionManifestProvenance, SectionVerbAllowlist, SectionVerbRef, SkillLifecycleSource,
    StateFamilyRef, ValidatedSectionManifest, decode_section_manifest, digest_to_hex,
    encode_section_manifest, execute_approved_plugin_section_install, pending_plugin_proposal_rows,
    propose_plugin_section_install, propose_plugin_section_install_with_evidence, quoted_leaf,
    render_pack_sections, render_plugin_proposal_row, render_plugin_proposal_section,
    render_plugin_row, render_plugin_sections, section_manifest_digest,
    validate_manifest_for_admission, validate_manifest_for_proposal,
};
pub use tasks::{
    CancelRejectionPathology, JobPresence, TaskBoardStatus, TaskIntentPresence, TaskRow,
    TasksSection, expand_task, failed_lane, fold_up_status, render_tasks_section,
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
