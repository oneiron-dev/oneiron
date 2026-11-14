//! Moved from `crates/oneiron/src/feedback/conversation_training/anonymous.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::conversation_training::anonymous::files::PieceFilesProblem;
use oneiron_vault_contract::conversation_training::PieceStateV1;
use serde::Deserialize;
use serde::Serialize;

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
pub mod files;
