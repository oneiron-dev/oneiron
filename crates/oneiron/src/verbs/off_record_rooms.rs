//! The typed room off-record doors (ARCH-0052 D5, PRIVACY-07).
//! These are the existing participant HTTP shapes. Each act uses the caller's
//! own credential and the room's live roster; no input chooses another vault.

use serde::{Deserialize, Serialize};

use crate::memory::MessageResultAttachment;
use crate::off_record::{
    OffRecordBackendClass, OffRecordMode, OffRecordNoticeAct, OffRecordTalkMessage,
};
use crate::share_travel::{CopyRefs, CopyTravelChoice};

mod copy;

/// A person, or an agent within its Write Grant, starts an off-record
/// stretch in a room they belong to (FIX 4596).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRoomStartRequest {
    pub room: String,
    /// The host's own name for the stretch, 1 to 256 bytes.
    pub session_ref: String,
    pub backend: OffRecordBackendClass,
}

/// One stretch in one room; the caller's credential supplies the participant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRoomRequest {
    pub room: String,
    pub session_ref: String,
}

/// `vault.off_record.rooms.export`'s input: one stretch in one room, and
/// whether the copy carries its vault refs (FIX 1199). An absent choice,
/// `{}` and `{"refs": "preserve"}` all make today's copy, byte for byte;
/// `{"refs": "omit"}` is the caller's own request for a copy without them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRoomExportRequest {
    pub room: String,
    pub session_ref: String,
    #[serde(default)]
    pub travel: Option<CopyTravelChoice>,
}

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

/// The stretch as the caller's membership shows it, without its talk.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomView {
    pub session_ref: String,
    pub room: Option<String>,
    pub started_by: Option<String>,
    pub mode: OffRecordMode,
    pub backend: OffRecordBackendClass,
    pub entered_at: String,
    pub closing: bool,
    pub notices: Vec<OffRecordRoomNotice>,
    pub waiting_suggestions: Vec<OffRecordRoomSuggestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomNotice {
    pub act: OffRecordNoticeAct,
    pub by: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomSuggestion {
    pub by: String,
    pub at: String,
}

/// What a holder's save wrote into this vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomSaved {
    pub saved: Vec<OffRecordRoomSavedTurn>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomSavedTurn {
    pub turn: String,
    pub replayed: Vec<String>,
    pub short_ids: Vec<OffRecordRoomShortIdPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomShortIdPair {
    pub room: String,
    pub vault: String,
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

/// A result's presentation in a copy without its vault refs: what the copy
/// already showed of it, under a copy-local `result-<n>` label, with no run,
/// occurrence, path, content handle or read facets to reach its body by.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRoomCopyResult {
    pub label: String,
    pub bytes: u64,
    /// `text` or `binary`.
    pub kind: String,
    pub lines: u64,
    pub complete: bool,
    /// The bounded preview the room showed, withheld as it was withheld.
    pub preview: String,
    pub preview_truncated: bool,
}

/// What a talk copy made without its vault refs left out (FIX 1199): the
/// choice it was made under and each ref slot of a copy with its refs that
/// it dropped or relabelled. It is a copy of what the caller could see,
/// never a complete archive of the stretch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomCopyLoss {
    /// The ref choice the copy was made under.
    pub refs: CopyRefs,
    pub slots: Vec<OffRecordRoomCopySlot>,
}

/// One ref slot a copy without its refs changed, and how many values of it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomCopySlot {
    /// The slot's path in a copy with its refs, as `turns[].speaker`.
    pub slot: String,
    pub handling: OffRecordRoomCopySlotHandling,
    pub count: usize,
}

/// How a copy without its refs changed a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordRoomCopySlotHandling {
    /// Left out of the copy.
    Dropped,
    /// Replaced by a copy-local label.
    Labelled,
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
