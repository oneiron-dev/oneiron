//! Room bodies, membership windows, session presence and audience visibility.
mod attendee;
mod body;
mod chat_breakpoint;
mod deletion;
mod live_speakers;
mod membership;
mod output_guard;
mod preview;
mod privacy_erase;
mod roles;
mod session;
// An owner-named residual speaker handed into a PERSON window (FIX 3634).
mod speaker_handoff;
mod turn_actions;
mod visibility;

pub use attendee::{ContainerAttendee, ContainerAttendeeEntry, ContainerAttendeeEvent};
pub use body::{ConversationBody, ConversationKind, RoomRole};
pub(crate) use body::{body_in, create_in_txn, fresh_id_in_txn, validate_put_in_txn};
pub(crate) use chat_breakpoint::erase_chat_breakpoints_in_txn;
pub use chat_breakpoint::{
    ChatBreakpoint, ChatBreakpointRung, ChatBreakpointStale, chat_breakpoint,
    chat_breakpoint_stands, keep_chat_breakpoint,
};
pub(crate) use deletion::ROOM_ERASURES;
pub(crate) use deletion::{
    guard_room_message_delete, pin_room_message_edge, record_author, replay_room_message_tombstone,
    room_message_owner_in, room_person_write_allowed,
};
pub use live_speakers::{LiveSpeakerCall, RoomLiveSpeakerEntries};
pub(crate) use live_speakers::{LiveSpeakers, RequiredSpeaker, required_live_speakers};
pub use membership::{HistoryChoice, MembershipAction, MembershipRow, MembershipWindow};
pub(crate) use output_guard::ContainerOutputGuard;
pub use output_guard::OutputMark;
pub(crate) use preview::{LatestMessage, PreviewCandidates, snippet, turn_text};
pub use privacy_erase::RoomPersonEraseOutcome;
pub(crate) use roles::{RoomHost, room_host_in_txn};
pub use session::{SessionMode, SessionPresence};
pub use speaker_handoff::{SpeakerHandoff, SpeakerHandoffBoundary, SpeakerHandoffReceipt};
pub use turn_actions::{
    TURN_ACTION_ATTEMPT_KIND, TurnAction, TurnActionAttempt, TurnActionAuthority,
    TurnActionContext, TurnActionLine, TurnActionRebindReceipt, TurnActionRebindRequest,
    TurnActionReceipt, TurnActionRequest,
};
pub(crate) use visibility::{
    AudienceCache, anchors_own_windows_admit_in, conversation_summary_covers,
    gate_claim_anchors_in, gate_claim_anchors_store_in, private_thread_word_turns_in,
    private_threads_readable_with_read_in, room_for_record_in,
};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{RecordError, Result};
use crate::{EntityId, Error, Vault, WriteActor};
use serde::{Serialize, de::DeserializeOwned};

use crate::store::conversation_body::invalid;
fn state(reason: &'static str) -> Error {
    Error::Record(RecordError::ConversationState(reason))
}
fn denied() -> Error {
    Error::Record(RecordError::ConversationDenied)
}
use crate::store::conversation_body::decode;
use crate::store::conversation_body::encode;
fn require_kind(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId, kind: u8) -> Result<Vec<u8>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live() {
        return Err(Error::EntityNotFound);
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != kind {
        return Err(invalid("entity kind"));
    }
    if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
        return Err(Error::EntityNotFound);
    }
    Ok(raw.to_vec())
}
fn authorize(vault: &Vault, txn: &heed::RoTxn<'_>, actor: WriteActor) -> Result<()> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor.entity_ref())?.is_live() {
        return Err(denied());
    }
    crate::memory::verify_actor_binding_in_txn(vault, txn, actor.entity_ref(), actor.actor_class())
        .map_err(|_| denied())
}

#[cfg(test)]
mod tests;

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::chat_breakpoint::chat_breakpoint_accepts_masked;

pub mod voice_roster;
