//! The anonymous training window's side of local custody (TL-6, FIX 5813):
//! where each anonymous piece stands at the intake, kept inline in its
//! submission's custody row, and the Vault doors the self-host shipper works
//! through. The shipper itself (HTTP, windows, file reads) is the server's;
//! it reads the released files and calls these doors, and nothing here
//! sends a byte.
//!
//! A submission's [`TrainingTransport`] is set at its first preparation and
//! kept by every retry: a self-hosted vault's offers are
//! [`TrainingTransport::Anonymous`], a managed vault's are
//! [`TrainingTransport::Hosted`]. A hosted row never touches its
//! [`AnonymousPiece`], and the hosted V2 path is as it was.
//!
//! An anonymous piece's standing (CALLS TL6_RESTORE_CLASS) rides its row in
//! the LIVE custody family, so no table of its own: the last signed revision
//! and state, the signed upload cursor, whether the intake ever took it
//! whole, and the durable withdrawal intent every local withdrawal cause
//! sets in the same write that withdraws the row. A signed state never
//! clears that intent, and its C, stored once at the first preparation,
//! needs no key to be withdrawn, so a restore that lost K still reaches it.
//! No V2 control names an anonymous piece: no forget or world control lists
//! it, an anonymous-only scope records no purge control, and no orphaned
//! generation counts its withdrawal unavailable.
//!
//! Its outbox files (CALLS TL6_ANON_FILE_RETENTION) stay while the piece
//! uploads or reads unknown or accepted; they go once the intake signed it
//! final (rejected, conflict or invalid: never sent again, FIX 7414, as a
//! hosted rejected offer's go), once the re-filter answered (eligible or
//! refused), once it is removed, or once it is withheld or withdrawn here,
//! through the outbox's own purge. The row, its C and its withdrawal intent
//! outlive them. No log names a C, a scope or a code.
//!
//! No C is ever sealed under twice. When the intake answers
//! `recipient_refresh_required` for a piece it holds no accepted facts for,
//! the piece is withheld with its withdrawal intent and its refresh asked
//! (CALLS TL6_ANON_REFRESH), and its source is offered anew at the next
//! offer pass as a new submission under a new C.
//!
//! A released piece whose outbox files are missing or not what its manifest
//! says ships nothing; the shipper records that on its row as a typed local
//! problem for the owner's view, and clears it once a window ships (FIX
//! 6916, `files`). It is never a signed field's, and nothing re-offers it.

mod apply;
mod files;
mod pages;

pub use self::apply::{AnonymousApplied, AnonymousRefusal};
pub(super) use self::files::files_problem;
pub use self::files::{AnonymousFilesSeen, PieceFilesProblem};
pub use self::pages::{
    ANONYMOUS_PAGE, AnonymousStatusWork, AnonymousUploadWork, AnonymousWithdrawalWork,
};

use oneiron_vault_contract::conversation_training::{PieceCursorV1, PieceStateV1};
use serde::{Deserialize, Serialize};

use self::files::PieceFilesMark;
use super::custody::{SubmissionCustody, SubmissionState};

/// How a submission's offer leaves the vault (TL-6), set at its first
/// preparation from the offer pass and kept by every retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingTransport {
    /// Through the outbox's V2 files, which a managed vault's supervisor
    /// ships under its own binding.
    Hosted,
    /// Through the anonymous training window, piece by piece under its C,
    /// which a self-hosted vault's shipper reaches.
    Anonymous,
}

/// Where an anonymous piece stands at the intake, as its signed receipts
/// say: E1's piece state without its fields, which the row keeps beside it.
/// Never a V2 receipt status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingPieceState {
    /// The intake holds part of the piece.
    Uploading,
    /// The piece is whole in the intake's quarantined custody: custody only,
    /// never eligibility.
    Accepted,
    /// The intake refused the piece: final for its C, so never sent again
    /// (FIX 7414).
    Rejected,
    /// A window changed what the intake already held: final for its C, so
    /// never sent again (FIX 7414).
    Conflict,
    /// The piece's facts or bytes made no valid submission: final for its
    /// C, so never sent again (FIX 7414).
    InvalidSubmission,
    /// The re-filter passed the piece.
    Eligible,
    /// The re-filter refused the piece.
    Refused,
    /// Withdrawn; the intake is removing every copy.
    RemovalPending,
    /// Withdrawn, and every copy removed.
    Removed,
    /// The intake's generic answer for a code it holds nothing for. Never a
    /// removal.
    Unknown,
}

impl TrainingPieceState {
    /// The state as the window and a door spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uploading => "uploading",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Conflict => "conflict",
            Self::InvalidSubmission => "invalid_submission",
            Self::Eligible => "eligible",
            Self::Refused => "refused",
            Self::RemovalPending => "removal_pending",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }

    /// The local mirror of a signed `state`.
    fn of(state: &PieceStateV1) -> Self {
        match state {
            PieceStateV1::Uploading { .. } => Self::Uploading,
            PieceStateV1::Accepted => Self::Accepted,
            PieceStateV1::Rejected { .. } => Self::Rejected,
            PieceStateV1::Conflict => Self::Conflict,
            PieceStateV1::InvalidSubmission => Self::InvalidSubmission,
            PieceStateV1::Eligible => Self::Eligible,
            PieceStateV1::Refused { .. } => Self::Refused,
            PieceStateV1::RemovalPending => Self::RemovalPending,
            PieceStateV1::Removed => Self::Removed,
            PieceStateV1::Unknown => Self::Unknown,
        }
    }
}

/// An anonymous piece's standing at the intake, inline in its custody row.
/// A hosted row keeps the default and never touches it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AnonymousPiece {
    /// The revision of the last signed receipt applied; 0 before any.
    pub(super) revision: u64,
    /// Where that receipt says the piece stands; `None` before any.
    pub(super) state: Option<TrainingPieceState>,
    /// Where the upload resumes, as the last signed `uploading` receipt said;
    /// `None` before one, and once the intake answers that it holds nothing.
    cursor: Option<AnonymousCursor>,
    /// Whether the intake ever signed the piece whole in its custody.
    pub(super) accepted: bool,
    /// The durable withdrawal intent: set by every local withdrawal cause,
    /// never cleared by a signed state. Its C is withdrawn until the intake
    /// signs it removed.
    pub(super) withdraw: bool,
    /// Whether the intake asked for the piece afresh
    /// (`recipient_refresh_required`): set only by
    /// [`Vault::anonymous_refresh_required`](crate::Vault::anonymous_refresh_required),
    /// never cleared. Its source then skips the offer pass's "same revision,
    /// withheld: skip" for this cause alone.
    pub(super) refresh_requested: bool,
    /// The reason the last signed receipt gave, for a rejection or the
    /// re-filter's refusal.
    pub(super) reason: Option<String>,
    /// When the intake signed the last receipt applied, unix seconds.
    pub(super) at: Option<u64>,
    /// A local problem with its outbox files the shipper found (FIX 6916):
    /// never signed, and no signed field's. Recorded and cleared through
    /// [`Vault::anonymous_piece_files`](crate::Vault::anonymous_piece_files).
    pub(super) files_problem: Option<PieceFilesMark>,
}

impl AnonymousPiece {
    /// The stored cursor, as the window spells it.
    fn cursor(&self) -> Option<PieceCursorV1> {
        self.cursor.map(AnonymousCursor::to_wire)
    }

    /// The sealed bytes the intake holds so far, while the piece uploads.
    pub(super) fn progress(&self) -> Option<u64> {
        self.cursor
            .filter(|_| self.state == Some(TrainingPieceState::Uploading))
            .map(|cursor| cursor.next_offset)
    }
}

/// E1's piece cursor, as the row keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct AnonymousCursor {
    /// The next part index the intake expects.
    next_index: u64,
    /// The stream offset the next part starts at.
    next_offset: u64,
    /// The next person index.
    persons_next: u64,
    /// The next world index.
    worlds_next: u64,
    /// The next chunk table index.
    chunks_next: u64,
    /// Whether the intake holds the head.
    head_received: bool,
}

impl AnonymousCursor {
    /// The row's copy of a signed `cursor`.
    const fn of(cursor: &PieceCursorV1) -> Self {
        Self {
            next_index: cursor.next_index,
            next_offset: cursor.next_offset,
            persons_next: cursor.persons_next,
            worlds_next: cursor.worlds_next,
            chunks_next: cursor.chunks_next,
            head_received: cursor.head_received,
        }
    }

    /// The cursor as the window spells it.
    const fn to_wire(self) -> PieceCursorV1 {
        PieceCursorV1 {
            next_index: self.next_index,
            next_offset: self.next_offset,
            persons_next: self.persons_next,
            worlds_next: self.worlds_next,
            chunks_next: self.chunks_next,
            head_received: self.head_received,
        }
    }
}

/// Sets the withdrawal intent of `row` when it is an anonymous piece, in
/// the caller's own write of the row; a hosted row is left as it is. Its C
/// is stored, so this needs no key, whatever its generation.
pub(super) fn withdraw(row: &mut SubmissionCustody) {
    if row.transport == TrainingTransport::Anonymous {
        row.anonymous.withdraw = true;
    }
}

/// CALLS TL6_ANON_FILE_RETENTION: whether an anonymous piece's outbox files
/// may go now. They stay while it is held, uploads, reads unknown or
/// accepted, and while its removal is pending; they go once the intake
/// signed it final (rejected, conflict or invalid: never sent again, FIX
/// 7414, as a hosted rejected offer's go), once the re-filter answered,
/// once it is removed, or once it is withheld or withdrawn here.
pub(super) fn files_due(row: &SubmissionCustody) -> bool {
    match row.state {
        SubmissionState::Held => false,
        SubmissionState::Withheld | SubmissionState::Withdrawn => true,
        SubmissionState::Published => matches!(
            row.anonymous.state,
            Some(
                TrainingPieceState::Rejected
                    | TrainingPieceState::Conflict
                    | TrainingPieceState::InvalidSubmission
                    | TrainingPieceState::Eligible
                    | TrainingPieceState::Refused
                    | TrainingPieceState::Removed
            )
        ),
    }
}

/// Whether `row` is an anonymous piece the intake asked to be offered anew
/// (`recipient_refresh_required`, its explicit cause): its source alone
/// skips the offer pass's "same revision, withheld: skip", and is offered
/// again as a new submission under a new C. Hosted retries are as they
/// were.
pub(super) fn refresh_requested(row: &SubmissionCustody) -> bool {
    row.transport == TrainingTransport::Anonymous && row.anonymous.refresh_requested
}
