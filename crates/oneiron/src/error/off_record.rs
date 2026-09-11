//! Off-record-domain errors: the kill switch, off-record session lifecycle,
//! the overlay and its leases, and the refusals that keep off-record turns out
//! of the on-record journal.
//!
//! Reached from the root as `Error::OffRecord(..)`, a transparent wrapper:
//! Display and `source()` are the leaf's, so every message string is what it
//! was when these variants sat flat on `Error`.

use super::ErrorKind;

/// Off-record-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OffRecordError {
    /// Off-record entry is disabled by the vault-level kill-switch. The
    /// refusal occurs before any in-process registry or overlay mutation.
    #[error("off-record sessions are disabled by configuration")]
    KillSwitchDisabled,
    /// Off-record session enter (OF-326) found an existing record for the
    /// session ref. Enter is explicit and single-shot; the ref frees up when
    /// the session closes.
    #[error("off-record session already exists: {session_ref}")]
    OffRecordSessionAlreadyExists { session_ref: String },
    /// An off-record session operation (OF-326) targeted a session ref with
    /// no live record (never entered, or already closed).
    #[error("off-record session not found: {session_ref}")]
    OffRecordSessionNotFound { session_ref: String },
    /// A mutator (tag, promote, note-context-receipt, mode flip) targeted an
    /// off-record session whose close is in flight — the closing flag froze
    /// the record so close's multi-transaction deletion pass cannot race a
    /// mutation. Nothing was written; the session is evaporating.
    #[error("off-record session {session_ref} is closing: the record is frozen")]
    OffRecordSessionClosing { session_ref: String },
    /// An in-memory session overlay insert would exceed its configured hard
    /// byte budget. The candidate mutation is not published.
    #[error(
        "off-record overlay is full: budget {budget_bytes} bytes, attempted {attempted_bytes} bytes"
    )]
    OffRecordOverlayFull {
        budget_bytes: usize,
        attempted_bytes: usize,
    },
    /// A generation-stamped session overlay lease was requested or used
    /// after the overlay began closing or was cleared.
    #[error("off-record overlay generation {generation} is closed")]
    OffRecordOverlayLeaseClosed { generation: u64 },
    /// Promote (OF-326 / ONE-1645) is a widening op: it moves a fenced turn
    /// into the durable vault, so it must be authenticated to the owner
    /// principal by the same actor-identity vocabulary as every other consent
    /// surface. The supplied actor did not authenticate the principal (ref
    /// mismatch, blank ref, or an unverified voice path). The fence stands and
    /// nothing was written.
    #[error(
        "off-record promote in session {session_ref} is not authenticated: actor {actor_ref} does not authenticate the owner principal"
    )]
    OffRecordPromoteUnauthenticated {
        session_ref: String,
        actor_ref: String,
    },
    /// ARCH-0052 D2 (ONE-1728, K4): an ORDINARY base write transaction decoded
    /// an op referencing an entity that is a live session-overlay member. The
    /// check runs INSIDE the applying transaction at the op-decode point, so
    /// the membership read and the write it authorizes see the same state and
    /// the whole batch aborts atomically — no base row is written. Only a
    /// promote-replay transaction may reference overlay ids, and only those of
    /// the session whose promote it is.
    #[error("base write rejected: {entity_ref} is a live off-record overlay member")]
    OffRecordTaintedBaseWrite { entity_ref: String },
    /// ARCH-0052 D2 backstop (a) (ONE-1728, K7): the canonical-handle witness
    /// door resolved a conversation that belongs to a live session overlay.
    /// Session-owned rooms are witnessed through the session handle only;
    /// the base door refuses before any write.
    #[error(
        "witness rejected: conversation {conversation_ref} belongs to live off-record session {session_ref}"
    )]
    OffRecordWitnessDoorRejected {
        session_ref: String,
        conversation_ref: String,
    },
    /// ARCH-0052 §7 (ONE-1729, K-EXEC; owner ruling R-20260807-02): the
    /// session-side EXECUTOR witness entry was handed a guest-supplied turn
    /// ref. Executor turns get their identity from the session, never from
    /// the guest, so this refuses BEFORE any `WitnessTurn` is constructed —
    /// zero overlay/base delta, zero gate decisions, in both modes. A host
    /// caller that legitimately wants guest transcript ingress must WIDEN
    /// that typed surface, which is a visible API change rather than a
    /// silent plumbing path.
    #[error(
        "executor witness rejected: off-record session {session_ref} takes turn identity from the session, not from a guest-supplied turn ref"
    )]
    OffRecordGuestTurnRefRejected { session_ref: String },
    /// OF-326 talk-only: the intent originated from a session currently in
    /// off-record mode, where outbound/commitment verbs are disabled. Exit
    /// prompt semantics — wanting the action means exiting off-record mode.
    #[error(
        "off-record session {session_ref} is talk-only: outbound and commitment verbs are disabled; exit off-record mode to take this action"
    )]
    OffRecordTalkOnly { session_ref: String },
    /// ARCH-0052 D4 (ONE-1730): promote was asked for a turn the session's
    /// typed journal carries no materialized TURN put for. The journal is the
    /// ONLY legal closure source, so an unknown turn has nothing to replay —
    /// and the refusal deliberately does not fall back on scanning overlay
    /// index keys, which are shared across turns.
    #[error("off-record promote found no journaled turn {turn_ref} to replay")]
    OffRecordTurnNotInJournal { turn_ref: String },
}

impl OffRecordError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::KillSwitchDisabled => ErrorKind::KillSwitchDisabled,
            Self::OffRecordSessionAlreadyExists { .. } => ErrorKind::OffRecordSessionAlreadyExists,
            Self::OffRecordSessionNotFound { .. } => ErrorKind::OffRecordSessionNotFound,
            Self::OffRecordSessionClosing { .. } => ErrorKind::OffRecordSessionClosing,
            Self::OffRecordOverlayFull { .. } => ErrorKind::OffRecordOverlayFull,
            Self::OffRecordOverlayLeaseClosed { .. } => ErrorKind::OffRecordOverlayLeaseClosed,
            Self::OffRecordPromoteUnauthenticated { .. } => {
                ErrorKind::OffRecordPromoteUnauthenticated
            }
            Self::OffRecordTaintedBaseWrite { .. } => ErrorKind::OffRecordTaintedBaseWrite,
            Self::OffRecordWitnessDoorRejected { .. } => ErrorKind::OffRecordWitnessDoorRejected,
            Self::OffRecordGuestTurnRefRejected { .. } => ErrorKind::OffRecordGuestTurnRefRejected,
            Self::OffRecordTalkOnly { .. } => ErrorKind::OffRecordTalkOnly,
            Self::OffRecordTurnNotInJournal { .. } => ErrorKind::OffRecordTurnNotInJournal,
        }
    }
}
