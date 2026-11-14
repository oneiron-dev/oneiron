//! Moved from `crates/oneiron/src/verbs/off_record_rooms.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::off_record::lifecycle::types::OffRecordBackendClass;
use crate::off_record::lifecycle::types::OffRecordMode;
use crate::off_record::lifecycle::types::OffRecordNoticeAct;
use crate::share_travel::copy::CopyRefs;
use crate::share_travel::copy::CopyTravelChoice;
use serde::Deserialize;
use serde::Serialize;

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
