//! Public records, enums, constants and the executor-utterance label shared by all off-record children.

use serde::{Deserialize, Serialize};

use crate::receipt::ReceiptRecord;

pub(super) const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;

/// Longest accepted caller-supplied opaque session ref, in bytes.
pub(super) const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;

#[doc(hidden)]
pub use oneiron_verb_wire::off_record::lifecycle::types::{
    OffRecordBackendClass, OffRecordMode, OffRecordNoticeAct,
};

#[doc(hidden)]
pub use oneiron_records::off_record::lifecycle::types::{
    OffRecordNotice, OffRecordSaveSuggestion, OffRecordSessionRecord,
};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordTalkMessage {
    /// `user`, `companion` or `system`.
    pub author: String,
    pub message_type: String,
    pub content: String,
    pub order: u64,
    /// The result it carries in place of an answer too large to say (FIX
    /// 365), its preview withheld while the room's marks taint the body.
    pub result: Option<crate::memory::MessageResultAttachment>,
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
