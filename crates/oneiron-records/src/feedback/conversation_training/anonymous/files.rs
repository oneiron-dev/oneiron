//! Moved from `crates/oneiron/src/feedback/conversation_training/anonymous/files.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a released anonymous offer's outbox files ship nothing (FIX 6916):
/// a local problem the self-host shipper found, never a state the intake
/// signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PieceFilesProblem {
    /// A file is not there, or does not read.
    Missing,
    /// The manifest does not decode or names another submission, or a chunk
    /// file is not the length or the BLAKE3 the manifest gives.
    Mismatched,
}

impl PieceFilesProblem {
    /// The problem as a door spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
        }
    }
}
