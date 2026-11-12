//! Moved from `crates/oneiron/src/workspace_roster/rooms/thread_join.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::audience_events::ThreadAudienceHistory;
use crate::workspace_roster::rooms::*;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_store::conversation_body::ThreadBinding;
pub use oneiron_store::conversation_body::ThreadJoinRequestsRequest;

/// `vault.rooms.thread_join.request`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

/// `vault.rooms.thread_join.approve` and `.deny`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinDecisionRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The request's TURN, 32-hex.
    pub request_ref: String,
}

/// How a request to join stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreadJoinRequestState {
    /// No member answered it yet.
    Pending,
    /// The one who asked was added, by an approval or otherwise.
    Approved,
    /// A member denied it.
    Denied,
}

/// One request to join a private thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequestView {
    /// The thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The request's TURN, 32-hex.
    pub request_ref: String,
    /// Who asked, 32-hex.
    pub requester_ref: String,
    /// When they asked, Unix seconds.
    pub at: u64,
    pub state: ThreadJoinRequestState,
    /// The TURN that settled it, 32-hex; absent while it is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
}
