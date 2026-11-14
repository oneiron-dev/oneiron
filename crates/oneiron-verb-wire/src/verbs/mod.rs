//! Moved from `crates/oneiron/src/verbs/mod.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::affect::QueryAffect;
pub use crate::memory::recall::RecallRequest;
pub use crate::task_verb::TaskWaitRequest;
pub use crate::task_verb::fanout_batch::FanoutBatchInput;
pub use crate::task_verb::fanout_batch::FanoutChildInput;
pub use crate::task_verb::fanout_batch::FanoutSlotState;
pub use crate::task_verb::fanout_batch::FanoutSlotTerminal;
pub use crate::verbs::act_answer::*;
pub use crate::verbs::agent_grant::*;
pub use crate::verbs::agent_run_effect::*;
pub use crate::verbs::agents::*;
pub use crate::verbs::anonymous_chat::*;
pub use crate::verbs::answer_forward::*;
pub use crate::verbs::asr::*;
pub use crate::verbs::asset_masked_read::*;
pub use crate::verbs::authority_history::*;
pub use crate::verbs::board_layout::*;
pub use crate::verbs::calendar::*;
pub use crate::verbs::campaign_enrollment::*;
pub use crate::verbs::campaign_split::*;
pub use crate::verbs::can::*;
pub use crate::verbs::comm_widen::*;
pub use crate::verbs::connect_proposal::*;
pub use crate::verbs::connector::*;
pub use crate::verbs::connector_call::*;
pub use crate::verbs::connector_pack::*;
pub use crate::verbs::connector_reply_retry::*;
pub use crate::verbs::connector_slate::*;
pub use crate::verbs::connector_slate_revision::*;
pub use crate::verbs::connector_source_rows_read::*;
pub use crate::verbs::connector_witness_read_grant::*;
pub use crate::verbs::coreference::*;
pub use crate::verbs::courtesy_delete::*;
pub use crate::verbs::credential::*;
pub use crate::verbs::custody_drain::*;
pub use crate::verbs::diary::*;
pub use crate::verbs::diary_pinned::*;
pub use crate::verbs::disclosure::*;
pub use crate::verbs::embedding_space::*;
pub use crate::verbs::engine_controls::*;
pub use crate::verbs::eval_cohort::*;
pub use crate::verbs::explain::*;
pub use crate::verbs::fanout_launch::*;
pub use crate::verbs::federation::*;
#[cfg(feature = "sync")]
pub use crate::verbs::federation_burst::*;
pub use crate::verbs::feedback::*;
pub use crate::verbs::files::*;
pub use crate::verbs::follower_keyframe::*;
pub use crate::verbs::gate_decision_read::*;
pub use crate::verbs::git_push_grant::*;
pub use crate::verbs::goal_optimize::*;
pub use crate::verbs::grants::*;
pub use crate::verbs::host::*;
pub use crate::verbs::hub::*;
pub use crate::verbs::identity_topology::*;
pub use crate::verbs::legal_hold::*;
pub use crate::verbs::live_run::*;
pub use crate::verbs::live_voice::*;
pub use crate::verbs::memory_requests::*;
pub use crate::verbs::mesh::*;
pub use crate::verbs::model_settings::*;
pub use crate::verbs::note_history::*;
pub use crate::verbs::oauth_authorization::*;
pub use crate::verbs::off_record::*;
pub use crate::verbs::off_record_rooms::*;
pub use crate::verbs::off_record_runs::*;
pub use crate::verbs::outbound_call_erase::*;
pub use crate::verbs::outbox_diverged::*;
pub use crate::verbs::pack_preview::*;
pub use crate::verbs::persona::*;
pub use crate::verbs::proxy::*;
pub use crate::verbs::receipts_page::*;
pub use crate::verbs::record_erase::*;
pub use crate::verbs::reply::*;
#[cfg(feature = "sync")]
pub use crate::verbs::repo_copy_edit::*;
#[cfg(feature = "sync")]
pub use crate::verbs::repo_manifest_conflict::*;
pub use crate::verbs::research::*;
pub use crate::verbs::research_root::*;
pub use crate::verbs::reservoir_sources::*;
pub use crate::verbs::residence::*;
pub use crate::verbs::retrieval::*;
pub use crate::verbs::revisions_read::*;
pub use crate::verbs::root_requests::*;
pub use crate::verbs::scratchpad::*;
pub use crate::verbs::secret::*;
pub use crate::verbs::secret_custody::*;
pub use crate::verbs::secret_grant::*;
pub use crate::verbs::secret_use::*;
pub use crate::verbs::self_actor::*;
pub use crate::verbs::self_model_read::*;
pub use crate::verbs::self_verbs::*;
pub use crate::verbs::share::*;
pub use crate::verbs::shared::*;
pub use crate::verbs::shared_admin::*;
pub use crate::verbs::shared_members::*;
pub use crate::verbs::shared_policy::*;
pub use crate::verbs::skill_attribution::*;
pub use crate::verbs::skill_defaults::*;
pub use crate::verbs::skill_execution::*;
pub use crate::verbs::skill_fit::*;
pub use crate::verbs::skill_package_read::*;
pub use crate::verbs::skills::*;
pub use crate::verbs::standing::*;
pub use crate::verbs::support_grant::*;
#[cfg(feature = "sync")]
pub use crate::verbs::sync_quarantine::*;
pub use crate::verbs::trusted_contact::*;
pub use crate::verbs::uncertain_send::*;
pub use crate::verbs::voice_bank::*;
pub use crate::verbs::weave::*;
pub use crate::verbs::wire_health::*;
pub use crate::verbs::workspace::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomRequest {
    pub room_ref: String,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomRefRequest {
    pub room_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomTurnRequest {
    pub room_ref: String,
    pub turn_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomClaimRequest {
    pub room_ref: String,
    pub turn_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRefRequest {
    pub project_ref: String,
}

/// `vault.projects.goal.dismiss`'s input: the project and the proposal to
/// set aside.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalDismissRequest {
    pub project_ref: String,
    pub target: ProjectGoalDismissTarget,
}

/// What `vault.projects.goal.dismiss` sets aside: the preference one
/// tradeoff question proposed, under the goal claim the caller saw in force;
/// or a full goal proposal by its id, with the owner's reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectGoalDismissTarget {
    Preference {
        expected_goal_ref: String,
        question_digest: String,
    },
    Proposal {
        proposal_ref: String,
        reason: String,
    },
}

/// `vault.projects.route_tradeoff`'s input: the project TASK to ask on and
/// the skill proposal whose tradeoff question it carries.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectTradeoffRouteRequest {
    pub task_ref: String,
    pub proposal_ref: String,
}

/// `vault.rooms.host`: the room, and the live session whose participants
/// count as present beside the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostRequest {
    pub room_ref: String,
    #[serde(default)]
    pub session_ref: Option<String>,
}

/// `vault.companions.sharing.get`: a companion's PERSON and the contact her
/// source vault's clearance is about.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanionSharingRequest {
    pub companion_ref: String,
    pub contact_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRefRequest {
    pub workspace_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub task_ref: String,
}

/// `vault.projects.proposals`: the conversation whose project cards to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectConversationRequest {
    pub conversation_ref: String,
}

/// `vault.projects.dismiss_card`: one host-held project card.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardRequest {
    pub card_id: String,
}

/// `tasks.wave` (OF-427, ARCH-0068 RC5): an epic TASK cut into a wave of
/// TASKs by a planner agent, queued as one planning attempt. Who asks, and
/// the lease the wave runs under, are the host's, never request text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaveRequest {
    /// The epic TASK the wave realizes.
    pub epic_task_ref: String,
    /// The dispatchable agent definition that cuts the epic.
    pub planner_ref: String,
    pub objective: String,
    /// The planner's own constraints, passed to it as they are.
    #[serde(default)]
    pub constraints: serde_json::Value,
}

/// The planning attempt a `tasks.wave` queued, or the one an identical
/// request already queued.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskWaveReceipt {
    pub attempt_ref: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardRefreshRequest {
    pub frame_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardSubscriptionRequest {
    pub scopes: std::collections::BTreeSet<crate::context_board::stream::events::SubscriptionScope>,
}

/// The typed facade answer of `self.focus.refresh` on an attached run: the
/// one STREAM frame the refresh minted, a keyframe at its epoch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardFrameReply {
    pub frame: crate::context_board::stream::frames::BoardStreamFrame,
}

/// The typed facade answer of `self.focus.subscribe` and
/// `self.focus.unsubscribe` on an attached run: the run's board STREAM
/// connection and the scopes now active on it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardSubscriptionReply {
    pub connection: String,
    pub active: std::collections::BTreeSet<crate::context_board::stream::events::SubscriptionScope>,
}

/// `self.focus.wakes`'s spec on an attached run: it names nothing beside the
/// attachment; the run's own board STREAM connection is the queue read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardWakeRequest {}

/// The typed facade answer of `self.focus.wakes`: every wake queued for the
/// attached run's board STREAM connection, oldest first, each re-read under
/// the caller's credential at delivery. Taking them drains the queue; the
/// TASK or diary-read review each names remains the durable mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardWakeReply {
    pub wakes: Vec<crate::context_board::stream::wake::WakeEnvelope>,
    /// The wake opener the woken session appends after its own log, rendered
    /// at this delivery and never stored with a wake (FIX 15011). Absent when
    /// no wake is delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opener: Option<String>,
}

/// `vault.writes.pending`'s one input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `inbox.list`'s one input (OF-221): the exclusive entity-ID cursor a
/// previous page returned as `next_after`, and a page size
/// (`INBOX_PAGE_DEFAULT` when absent).
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxListRequest {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `inbox.mark`'s one input (OF-221): one delivered notification and the
/// mark to record for the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxMarkRequest {
    pub notification_ref: String,
    pub mark: crate::inbox::list::NotificationMark,
}
pub mod act_answer;
pub mod agent_grant;
pub mod agent_run_effect;
pub mod agents;
pub mod anonymous_chat;
pub mod answer_forward;
pub mod asr;
pub mod asset_masked_read;
pub mod authority_history;
pub mod board_layout;
pub mod calendar;
pub mod campaign_enrollment;
pub mod campaign_split;
pub mod can;
pub mod comm_widen;
pub mod connect_proposal;
pub mod connector;
pub mod connector_call;
pub mod connector_pack;
pub mod connector_reply_retry;
pub mod connector_slate;
pub mod connector_slate_revision;
pub mod connector_source_rows_read;
pub mod connector_witness_read_grant;
pub mod coreference;
pub mod courtesy_delete;
pub mod credential;
pub mod custody_drain;
pub mod diary;
pub mod diary_pinned;
pub mod disclosure;
pub mod embedding_space;
pub mod engine_controls;
pub mod eval_cohort;
pub mod explain;
pub mod fanout_launch;
pub mod federation;
#[cfg(feature = "sync")]
pub mod federation_burst;
pub mod feedback;
pub mod files;
pub mod follower_keyframe;
pub mod gate_decision_read;
pub mod git_push_grant;
pub mod goal_optimize;
pub mod grants;
pub mod host;
pub mod hub;
pub mod identity_topology;
pub mod legal_hold;
pub mod live_run;
pub mod live_voice;
pub mod memory_requests;
pub mod mesh;
pub mod model_settings;
pub mod note_history;
pub mod oauth_authorization;
pub mod off_record;
pub mod off_record_rooms;
pub mod off_record_runs;
pub mod outbound_call_erase;
pub mod outbox_diverged;
pub mod pack_preview;
pub mod persona;
pub mod proxy;
pub mod receipts_page;
pub mod record_erase;
pub mod reply;
#[cfg(feature = "sync")]
pub mod repo_copy_edit;
#[cfg(feature = "sync")]
pub mod repo_manifest_conflict;
pub mod research;
pub mod research_root;
pub mod reservoir_sources;
pub mod residence;
pub mod retrieval;
pub mod revisions_read;
pub mod root_requests;
pub mod scratchpad;
pub mod secret;
pub mod secret_custody;
pub mod secret_grant;
pub mod secret_use;
pub mod self_actor;
pub mod self_model_read;
pub mod self_verbs;
pub mod share;
pub mod shared;
pub mod shared_admin;
pub mod shared_members;
pub mod shared_policy;
pub mod skill_attribution;
pub mod skill_defaults;
pub mod skill_execution;
pub mod skill_fit;
pub mod skill_package_read;
pub mod skills;
pub mod standing;
pub mod support_grant;
#[cfg(feature = "sync")]
pub mod sync_quarantine;
pub mod trusted_contact;
pub mod uncertain_send;
pub mod voice_bank;
pub mod voice_records;
pub mod weave;
pub mod wire_health;
pub mod workspace;
