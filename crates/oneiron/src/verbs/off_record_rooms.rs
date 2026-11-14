//! The typed room off-record doors (ARCH-0052 D5, PRIVACY-07).
//! These are the existing participant HTTP shapes. Each act uses the caller's
//! own credential and the room's live roster; no input chooses another vault.

use serde::{Deserialize, Serialize};

use crate::memory::MessageResultAttachment;
use crate::off_record::OffRecordTalkMessage;

mod copy;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::off_record_rooms::{
    OffRecordRoomCopyLoss, OffRecordRoomCopyResult, OffRecordRoomCopySlot,
    OffRecordRoomCopySlotHandling, OffRecordRoomExportRequest, OffRecordRoomNotice,
    OffRecordRoomRequest, OffRecordRoomSavedTurn, OffRecordRoomShortIdPair,
    OffRecordRoomStartRequest, OffRecordRoomSuggestion, OffRecordRoomView,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRoomWitnessRequest {
    pub room: String,
    pub session_ref: String,
    /// Leave conversation_ref empty to use the stretch's own conversation.
    pub turn: crate::memory::WitnessTurn,
    #[serde(default)]
    pub summary: Option<String>,
}

/// What a holder's save wrote into this vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomSaved {
    pub saved: Vec<OffRecordRoomSavedTurn>,
}

impl From<crate::off_record::SavedTurns> for OffRecordRoomSaved {
    fn from(turns: crate::off_record::SavedTurns) -> Self {
        Self {
            saved: turns
                .into_iter()
                .map(|(turn, outcome)| OffRecordRoomSavedTurn {
                    turn: turn.to_hex(),
                    replayed: outcome
                        .replayed
                        .iter()
                        .map(crate::EntityId::to_hex)
                        .collect(),
                    short_ids: outcome
                        .short_id_mapping
                        .into_iter()
                        .map(|(room, vault)| OffRecordRoomShortIdPair { room, vault })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// A person's export attachment, restricted to the talk they could see. A
/// copy made without its vault refs (FIX 1199) names no stretch or room,
/// labels its turns, speakers and results within the copy, and says what
/// it left out in `copy`; a copy that carries its refs has no `copy`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomExport {
    /// The stretch's name in its room; absent from a copy without its refs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    pub room: Option<String>,
    pub exported_at: String,
    pub turns: Vec<OffRecordRoomExportTurn>,
    /// What a copy without its refs left out; absent from one with them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<OffRecordRoomCopyLoss>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomExportTurn {
    /// The turn's id; `turn-<n>` in a copy without its refs.
    pub turn: String,
    /// The speaker's id; `speaker-<n>` in a copy without its refs.
    pub speaker: Option<String>,
    pub occurred_at: String,
    pub saved: bool,
    pub messages: Vec<OffRecordRoomExportMessage>,
}

/// One visible message of a talk copy, field for field as the room holds
/// it ([`OffRecordTalkMessage`]).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomExportMessage {
    /// `user`, `companion` or `system`.
    pub author: String,
    pub message_type: String,
    pub content: String,
    pub order: u64,
    /// The result it carries in place of an answer too large to say.
    pub result: Option<OffRecordRoomExportResult>,
}

/// A message's result in a talk copy: the attachment as the room holds it,
/// or, in a copy without its vault refs, its presentation under a label.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum OffRecordRoomExportResult {
    Attached(MessageResultAttachment),
    Labelled(OffRecordRoomCopyResult),
}

impl From<OffRecordTalkMessage> for OffRecordRoomExportMessage {
    fn from(message: OffRecordTalkMessage) -> Self {
        Self {
            author: message.author,
            message_type: message.message_type,
            content: message.content,
            order: message.order,
            result: message.result.map(OffRecordRoomExportResult::Attached),
        }
    }
}
