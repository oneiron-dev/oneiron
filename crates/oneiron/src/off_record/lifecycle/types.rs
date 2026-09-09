//! Public records, enums, constants and the executor-utterance label shared by all off-record children.

use serde::{Deserialize, Serialize};

use crate::receipt::ReceiptRecord;

pub(super) const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;

/// Longest accepted caller-supplied opaque session ref, in bytes.
pub(super) const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;

/// The base and room-overlay halves of one additive VaultMeta counter
/// (ONE-1929).
#[cfg(test)]
pub(super) type VaultMetaCounterComponents = (Option<Vec<u8>>, Option<Vec<u8>>);

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
    /// [`Error::OffRecordSessionClosing`] — close drains leases and drops the
    /// overlay across several steps, and a mutation landing in that window
    /// would write into a room that is already going away.
    #[serde(default)]
    pub closing: bool,
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
    /// [`SessionLocalReceiptLog`] (RECEIPTS-FOLLOW-TRANSCRIPT).
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
}

impl ExecutorUtterance {
    /// Message-type string carried into the witness door.
    #[must_use]
    pub const fn as_message_type(self) -> &'static str {
        match self {
            Self::Speak => "executor.speak",
            Self::Think => "executor.think",
            Self::Express => "executor.express",
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
            Self::Think => false,
        }
    }
}
