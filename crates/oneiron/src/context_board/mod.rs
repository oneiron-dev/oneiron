//! Typed Context Board render projections.
//!
//! WORLDS, MEMORIES, TASKS, SKILLS, ROOM, INBOX, SCRATCHPAD, the cached
//! `people` roster, session read-set riders and stream projections.

mod capabilities;
mod children;
pub use children::{
    ChildState, ForkState, child_states_for_actor, fork_states_for_actor, render_you_line,
};
mod explain;
pub use explain::{GateExplanation, MemoryExplanation};
mod people;
pub(crate) use people::ensure_agent_person;
pub use people::{
    PEOPLE_PREFIX_BUDGET_TOK, People, PeoplePrefix, PeopleView, PersonKind, PersonRow,
};
mod inbox;
pub use inbox::assemble_inbox_section;
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
    ProposalReason, ServedLifecycle, ServedWhy, SessionReadSet,
};
pub(crate) use room::scope_worlds;
pub use room::{
    RoomBar, RoomMode, RoomPosture, RoomPresence, RoomSection, RosterParty, room_scope,
};
pub(crate) use room_verbs::{
    room_ceiling_in, room_clearance_in, room_reader_in, room_roster_in, thread_ceiling_in,
    thread_reader_in,
};
pub use worlds::{WorldPresence, WorldsSection, world_set_scope};
mod frame;
mod history;
mod hydration;
mod self_brief;
pub use history::{
    BoardHistoryError, BoardSelection, BoardTurn, BoardTurnReceipt, ReconstructedBoard,
};
pub(crate) use history::{fold_board_turns_in_txn, validate_board_claim};
pub use self_brief::{
    BriefPlacement, BriefSkillRow, ClassLimit, ClassVerdict, CommunicationLimits, PlacedSelfBrief,
    SelfBrief, SelfBriefInput, SelfBriefSession, SelfBriefState,
};
mod hook_pins;
mod memories;
mod memories_frame;
mod memories_projection;
mod memory_pins;
pub use hook_pins::HookPin;
mod notifications;
pub use memories::MemoryTier;
pub use memories_frame::assemble_memories_sections;
mod plugin;
mod readers;
mod scratchpad;
mod stream;

pub(crate) use scratchpad::sealed_pad_review_text;
pub use scratchpad::{
    SCRATCHPAD_LINE_MAX_BYTES, SCRATCHPAD_RECALL_LINES, ScratchpadAppendReceipt, ScratchpadBoard,
    ScratchpadMark, ScratchpadRecall, ScratchpadRecallLine,
};
pub(crate) use scratchpad::{erase_scratchpad_rows_in_txn, scratchpad_erase_scope_exists};

pub use stream::{
    AppliedStreamState, BoardEvent, BoardRenderMode, BoardSnapshot, BoardStreamFrame,
    BoardStreamRegistry, CarrierCoalesceBuffer, CoalesceOutcome, CommittedTaskBoardState,
    DeliveryClass, DeliveryPolicy, DeltaRow, FrameApplyOutcome, FrameEnqueueOutcome, FrameKind,
    RouteObservation, StreamConnectionId, StreamConnectionState, SubscriptionError,
    SubscriptionReceipt, SubscriptionScope, WakeEnvelope,
};
#[cfg(test)]
mod surfaces_tests;
mod tasks;

pub use frame::{
    BoardBlockHeader, BoardBudget, BoardBudgetRequest, BoardBudgetSource, BoardFrame,
    BoardFrameError, BoardLegend, BoardRender, BoardRenderMetadata, BoardSection, BudgetPolicyRef,
    CANONICAL_BOARD_LEGEND, CORE_SHED_ORDER, MAX_BOARD_ROW_BYTES, PLUGIN_SECTION_BUDGET_POLICY_REF,
    SHED_ORDER, SectionPolicy, SectionView, ShedOutcome, ShedRank, ShedSection,
    TASK_LABEL_MAX_BYTES, TASK_ROW_FIXED_TOKEN_BYTES, assemble_tasks_section, render_board_block,
    resolve_board_budget, section_policy_for_budget_ref, shed,
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
    TasksSection, TasksSectionRows, expand_task, failed_lane, fold_up_status, render_tasks_section,
};
pub(crate) use tasks::{ack_task_in_txn, cancel_task_in_txn, task_is_acked, task_is_cancelled};

/// Collapse control characters and the Unicode line and paragraph separators
/// (which are not controls) so a rendered row is always one physical line,
/// even for a consumer that splits on U+2028/U+2029 (F31).
pub(super) fn one_line_token(s: &str) -> String {
    s.chars()
        .map(|character| {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                character
            }
        })
        .collect()
}
