pub use crate::workspace_roster::rooms::liveness::RoomThread;
pub use crate::workspace_roster::rooms::liveness::RoomThreadAudienceEvent;
pub use crate::workspace_roster::rooms::liveness::RoomThreadAudienceOp;
pub use crate::workspace_roster::rooms::liveness::RoomThreadList;
pub use crate::workspace_roster::rooms::liveness::RoomThreadWait;
pub use crate::workspace_roster::rooms::liveness::RoomThreads;
pub use crate::workspace_roster::rooms::liveness::RoomWaitKind;
pub use crate::workspace_roster::rooms::offers::OfferState;
pub use crate::workspace_roster::rooms::offers::OfferVoteTally;
pub use crate::workspace_roster::rooms::upkeep::RoomUpkeepInput;
pub use crate::workspace_roster::rooms::upkeep::RoomUpkeepThread;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::conversation_body::ThreadJoinRequestsRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_doors::ThreadAudienceAddRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_doors::ThreadAudienceReceipt;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_doors::ThreadAudienceRemoveRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_events::ThreadAudienceHistory;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_history::ThreadAudienceOpenFullHistoryRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::HostPin;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::HostPinKind;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::ProjectRoomPlace;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::RoomHostHand;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::RoomHostPin;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::RoomHosting;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::RoomSpeakingRole;
pub use oneiron_verb_wire::workspace_roster::rooms::hosting::RoomStanding;
pub use oneiron_verb_wire::workspace_roster::rooms::offer_activity::OfferVoteRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::offer_reopen::OfferReopenRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::offer_settle::OfferAnswer;
pub use oneiron_verb_wire::workspace_roster::rooms::offer_settle::OfferAnswerRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::offers::OffersRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::participants::ParticipantsRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::pins::RoomPinPolicySet;
pub use oneiron_verb_wire::workspace_roster::rooms::pins::RoomPinReply;
pub use oneiron_verb_wire::workspace_roster::rooms::pins::RoomPinRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::pins::RoomUnpinReply;
pub use oneiron_verb_wire::workspace_roster::rooms::private_threads::PrivateThreadMetadata;
pub use oneiron_verb_wire::workspace_roster::rooms::private_threads::RoomPrivateThreadsRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_delete::PrivateThreadDeleteReceipt;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_delete::PrivateThreadDeleteRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_history::RoomMessagesRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_join::ThreadJoinDecisionRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_join::ThreadJoinRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_join::ThreadJoinRequestState;
pub use oneiron_verb_wire::workspace_roster::rooms::thread_join::ThreadJoinRequestView;
pub use oneiron_verb_wire::workspace_roster::rooms::upkeep_voice::RoomUpkeepNudge;
pub use oneiron_verb_wire::workspace_roster::rooms::upkeep_voice::RoomUpkeepPendingRequest;
pub use oneiron_verb_wire::workspace_roster::rooms::upkeep_voice::RoomUpkeepVoiceRequest;
use serde::Deserialize;
use serde::Serialize;

pub mod audience_events;

/// A delivered TASK's durable result, attached to its trunk on a room read.
/// The TASK terminal register holds the fact; no second row is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomTrunkHeader {
    pub thread: EntityId,
    pub task: EntityId,
    pub result_ref: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomThreadPage {
    pub rows: Vec<EntityId>,
    /// Explicit end marker: `None` means the room has no further page.
    pub next_after: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomClaimReceipt {
    pub room_id: String,
    pub turn_id: String,
    pub actor: String,
    pub receipt_ref: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomClaimOutcome {
    Claimed(RoomClaimReceipt),
    HeldBy(RoomClaimReceipt),
    NotAddressed,
}
pub mod liveness;
pub mod offers;
pub mod replica;
pub mod upkeep;
