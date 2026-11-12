//! Moved from `crates/oneiron/src/workspace_roster/rooms/audience_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::audience_events::ThreadAudienceHistory;
use crate::workspace_roster::rooms::*;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_store::conversation_body::ThreadBinding;

/// `vault.rooms.thread_audience.add`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceAddRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The PERSON or AGENT_DEF added, 32-hex.
    pub person_ref: String,
    /// What the added person reads: the whole thread, or its turns from this
    /// add on. A walk-in reads from now on whatever this asks (FIX 6381), and
    /// so does an Admin's add from outside the thread; a self re-add, and an
    /// Admin's outside add for someone already in, change nothing.
    pub history: ThreadAudienceHistory,
}

/// `vault.rooms.thread_audience.remove`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceRemoveRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The PERSON or AGENT_DEF removed, 32-hex.
    pub person_ref: String,
}

/// What an audience edit wrote: its thread's root and the edit's own TURN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceReceipt {
    pub thread_ref: String,
    pub event_ref: String,
    /// What the person the edit names reads of the thread after it, the
    /// history that applied (FIX 6381): `from_now` for a walk-in that
    /// entered whatever its call asked, as before for one already in.
    /// Absent on a remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<ThreadAudienceHistory>,
}
