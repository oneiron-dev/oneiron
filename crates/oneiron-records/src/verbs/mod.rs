//! Moved from `crates/oneiron/src/verbs/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::verbs::agent_grant::*;
pub use crate::verbs::answer_forward::*;
pub use crate::verbs::connector_call::*;
pub use crate::verbs::custody_drain::*;
pub use crate::verbs::explain::*;
pub use crate::verbs::host::*;
pub use crate::verbs::live_voice::*;
pub use crate::verbs::memory_requests::*;
pub use crate::verbs::outbox_diverged::*;
pub use crate::verbs::record_erase::*;
pub use crate::verbs::residence::*;
pub use crate::verbs::scratchpad::*;
pub use crate::verbs::secret_custody::*;
pub use crate::verbs::shared_members::*;
pub use oneiron_verb_wire::memory::affect::QueryAffect;
pub use oneiron_verb_wire::memory::recall::RecallRequest;
pub use oneiron_verb_wire::task_verb::TaskWaitRequest;
pub use oneiron_verb_wire::task_verb::fanout_batch::FanoutBatchInput;
pub use oneiron_verb_wire::task_verb::fanout_batch::FanoutChildInput;
pub use oneiron_verb_wire::task_verb::fanout_batch::FanoutSlotState;
pub use oneiron_verb_wire::task_verb::fanout_batch::FanoutSlotTerminal;
pub use oneiron_verb_wire::verbs::BoardFrameReply;
pub use oneiron_verb_wire::verbs::BoardRefreshRequest;
pub use oneiron_verb_wire::verbs::BoardSubscriptionReply;
pub use oneiron_verb_wire::verbs::BoardSubscriptionRequest;
pub use oneiron_verb_wire::verbs::BoardWakeReply;
pub use oneiron_verb_wire::verbs::BoardWakeRequest;
pub use oneiron_verb_wire::verbs::CompanionSharingRequest;
pub use oneiron_verb_wire::verbs::EmptyRequest;
pub use oneiron_verb_wire::verbs::InboxListRequest;
pub use oneiron_verb_wire::verbs::InboxMarkRequest;
pub use oneiron_verb_wire::verbs::ProjectCardRequest;
pub use oneiron_verb_wire::verbs::ProjectConversationRequest;
pub use oneiron_verb_wire::verbs::ProjectGoalDismissRequest;
pub use oneiron_verb_wire::verbs::ProjectGoalDismissTarget;
pub use oneiron_verb_wire::verbs::ProjectRefRequest;
pub use oneiron_verb_wire::verbs::ProjectTradeoffRouteRequest;
pub use oneiron_verb_wire::verbs::ReceiptsRequest;
pub use oneiron_verb_wire::verbs::RoomClaimRequest;
pub use oneiron_verb_wire::verbs::RoomHostRequest;
pub use oneiron_verb_wire::verbs::RoomRefRequest;
pub use oneiron_verb_wire::verbs::RoomRequest;
pub use oneiron_verb_wire::verbs::RoomTurnRequest;
pub use oneiron_verb_wire::verbs::TaskRequest;
pub use oneiron_verb_wire::verbs::TaskWaveReceipt;
pub use oneiron_verb_wire::verbs::TaskWaveRequest;
pub use oneiron_verb_wire::verbs::WorkspaceRefRequest;
use serde::Deserialize;
use serde::Serialize;

/// `vault.projects.goal.dismiss`'s result: `false` when an identical retry
/// wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGoalDismissReceipt {
    pub dismissed: bool,
}

/// `vault.projects.dismiss_card`'s result: `false` when the card was
/// dismissed already.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardDismissal {
    pub card_id: String,
    pub dismissed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub id: String,
    pub room: oneiron_store::conversation_body::ProjectRoom,
}
pub mod agent_grant;
pub mod answer_forward;
pub mod connector_call;
pub mod custody_drain;
pub mod explain;
pub mod host;
pub mod live_voice;
pub mod memory_requests;
pub mod outbox_diverged;
pub mod record_erase;
pub mod residence;
pub mod scratchpad;
pub mod secret_custody;
pub mod shared_members;
