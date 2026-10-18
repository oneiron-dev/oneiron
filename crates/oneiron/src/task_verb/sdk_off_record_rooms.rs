//! The typed room off-record doors (ARCH-0052 D5, PRIVACY-07).
//! These are the existing participant HTTP shapes. Each act uses the caller's
//! own credential and the room's live roster; no input chooses another vault.

use serde::{Deserialize, Serialize};

use crate::off_record::{
    OffRecordBackendClass, OffRecordMode, OffRecordNoticeAct, OffRecordTalkMessage,
};

/// A person starts an off-record stretch in a room they belong to.
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

/// A person's export attachment, restricted to the talk they could see.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomExport {
    pub session_ref: String,
    pub room: Option<String>,
    pub exported_at: String,
    pub turns: Vec<OffRecordRoomExportTurn>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRoomExportTurn {
    pub turn: String,
    pub speaker: Option<String>,
    pub occurred_at: String,
    pub saved: bool,
    pub messages: Vec<OffRecordTalkMessage>,
}
