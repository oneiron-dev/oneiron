//! Public records, enums, constants and the executor-utterance label shared by all off-record children.

use serde::{Deserialize, Serialize};

use crate::receipt::ReceiptRecord;

pub(super) const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;

/// Longest accepted caller-supplied opaque session ref, in bytes.
pub(super) const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;

/// Current write-routing mode of an off-record session.
///
/// The mode says where NEW writes land. It never moves rows: flipping to
/// [`OffRecordMode::OnRecord`] seals the overlay so later writes go to base,
/// and the room's earlier turns stay overlay-only until promote or close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordMode {
    OffRecord,
    OnRecord,
    /// No transcript, derived memory, telemetry, or receipts are retained.
    /// Entry is explicit; this mode cannot be changed or promoted.
    Anonymous,
}

impl OffRecordMode {
    pub(crate) const fn write_target(self) -> crate::session_overlay::RouteTarget {
        match self {
            Self::OffRecord => crate::session_overlay::RouteTarget::Overlay,
            Self::OnRecord => crate::session_overlay::RouteTarget::Base,
            Self::Anonymous => crate::session_overlay::RouteTarget::Discard,
        }
    }
}

/// Backend class the disclosure-honesty line is relative to (OF-326
/// EF-316-style honesty caveat): evaporation is backend-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordBackendClass {
    /// Local inference: real evaporation — nothing leaves the device and
    /// nothing survives close.
    Local,
    /// Cloud or BYO-key inference: this engine persists nothing at close,
    /// but provider retention applies to what transited the provider API.
    RemoteProvider,
}

/// Read-only projection of one in-process off-record session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordSessionRecord {
    pub version: u8,
    pub session_ref: String,
    pub mode: OffRecordMode,
    pub backend: OffRecordBackendClass,
    pub entered_at: u64,
    /// Turns promoted into base; close keeps them.
    pub promoted_turns: Vec<[u8; 16]>,
    /// Set by the first close transaction. While `true`, every mutator
    /// (promote, mode flip, emit-receipt record) rejects with
    /// [`OffRecordError::OffRecordSessionClosing`](crate::error::OffRecordError::OffRecordSessionClosing) — close drains leases and drops the
    /// overlay across several steps, and a mutation landing in that window
    /// would write into a room that is already going away.
    #[serde(default)]
    pub closing: bool,
    /// The room (a conversation) this stretch runs in, when a participant
    /// started it there. `None` is the stretch a vault's owner entered alone:
    /// a 1:1 with their own companion, where no other person is present.
    #[serde(default)]
    pub room: Option<[u8; 16]>,
    /// The person who started the stretch in its room.
    #[serde(default)]
    pub started_by: Option<[u8; 16]>,
    /// The room's timeline of saves, exports and save suggestions (ARCH-0052
    /// D5, the notice model), oldest first. Only a stretch in a room has
    /// one: a 1:1 posts no notice. It names who and what, never the content,
    /// and it evaporates with the room.
    #[serde(default)]
    pub notices: Vec<OffRecordNotice>,
}

/// What a person did with the talk, as the room hears of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordNoticeAct {
    /// Saved the whole talk so far into their own vault.
    SavedTalk,
    /// Saved one turn into their own vault.
    SavedTurn,
    /// Put the room on record: later turns are saved as they land.
    SavingFromHere,
    /// Took an export file of the talk.
    Exported,
    /// An agent suggested a save. Nothing was saved.
    SaveSuggested,
}

/// One notice in the room's timeline: who did what, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordNotice {
    pub act: OffRecordNoticeAct,
    /// The person or agent that acted.
    pub by: [u8; 16],
    pub at: u64,
}

/// A copy of the talk, as one person may keep it (ARCH-0052 D5): every
/// turn in the room they were a member for, saved or not, in the order the
/// room took them, with each turn's visible messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordTalk {
    pub session_ref: String,
    pub room: Option<[u8; 16]>,
    pub turns: Vec<OffRecordTalkTurn>,
}

/// One turn of a talk copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordTalkTurn {
    pub turn: [u8; 16],
    /// The person or agent who spoke it; `None` when it holds only system
    /// messages.
    pub speaker: Option<[u8; 16]>,
    pub occurred_at: u64,
    /// Whether someone already saved this turn into this vault.
    pub saved: bool,
    pub messages: Vec<OffRecordTalkMessage>,
}

/// One visible message of a talk copy. Hidden messages (an agent's own
/// reasoning) stay out of every copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordTalkMessage {
    /// `user`, `companion` or `system`.
    pub author: String,
    pub message_type: String,
    pub content: String,
    pub order: u64,
}

/// What evaporated at close and what was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffRecordCloseOutcome {
    /// Transcript entity puts that evaporated with the room (journal roles
    /// `TurnPut`, `MessagePartOf`, `SummaryDerivedFrom`), counted in the
    /// pre-close census. Close deletes nothing from base; these rows stopped
    /// existing because the overlay that held them did.
    pub turns_deleted: usize,
    /// Session-local retrieval-run context receipts evaporated: the count of
    /// retrieval-run receipt rows present in the overlay `VaultMeta` keyspace
    /// immediately BEFORE the overlay closes (the rows are unobservable after,
    /// and evaporation is what deletes them).
    pub context_receipts_deleted: usize,
    /// Emit-adjacent receipts dropped with the session's
    /// [`SessionLocalReceiptLog`](crate::receipt::SessionLocalReceiptLog) (RECEIPTS-FOLLOW-TRANSCRIPT).
    pub emit_receipts_deleted: usize,
    /// Emit receipts recorded after flipping the session on record.
    pub emit_receipts_retained: Vec<ReceiptRecord>,
    /// Turns promoted into base before close, left in place.
    pub promoted_turns_kept: usize,
}

/// What one executor turn is (ONE-1729, K-EXEC).
///
/// A LABEL, not a schema. The turn's shape — conversation identity, container
/// resolution, role tags, session routing — belongs to the facade witness
/// door; this only says which of the three utterances the door is forming, so
/// the executor never grows a transcript surface of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorUtterance {
    /// Addressed to the user.
    Speak,
    /// Reasoning the run kept for itself.
    Think,
    /// Non-verbal expression accompanying a turn.
    Express,
    /// Host-selected, hidden receipt for the report-blocked effect.
    ReportBlocked,
}

impl ExecutorUtterance {
    /// Message-type string carried into the witness door.
    #[must_use]
    pub const fn as_message_type(self) -> &'static str {
        match self {
            Self::Speak => "executor.speak",
            Self::Think => "executor.think",
            Self::Express => "executor.express",
            Self::ReportBlocked => crate::code_run::blocked::BLOCKED_REPORT_MESSAGE_TYPE,
        }
    }

    /// Whether the bubble this utterance forms is shown to the user.
    ///
    /// Speak and express are both ADDRESSED — one in words, one not — so both
    /// are visible. Think is the run's own reasoning: it is durably witnessed,
    /// and deliberately not shown.
    #[must_use]
    pub const fn is_visible(self) -> bool {
        match self {
            Self::Speak | Self::Express => true,
            Self::Think | Self::ReportBlocked => false,
        }
    }
}
