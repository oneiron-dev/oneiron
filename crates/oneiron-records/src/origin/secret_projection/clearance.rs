//! Moved from `crates/oneiron/src/origin/secret_projection/clearance.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

/// CALL H: the reason code of a diff that edits a sealed-file placeholder.
pub const SEALED_FILE_EDITED: &str = "sealed_file_edited";

/// CALL H, exactly: the status line beside [`SEALED_FILE_EDITED`].
pub const SEALED_FILE_EDITED_STATUS: &str = "This diff edits a sealed-file placeholder. Grant real-byte reveal for this file, or have the \
     owner approve this exact replacement.";

/// ASK E: the reason code of a diff with no unique mapping onto the
/// original.
pub const PROJECTION_EDIT_CONFLICT: &str = "projection_edit_conflict";

/// CALL 2, exactly: the status line beside [`PROJECTION_EDIT_CONFLICT`].
pub const PROJECTION_EDIT_CONFLICT_STATUS: &str = "This diff does not map uniquely to the original file. Submit an exact or rebased proposal, \
     grant real-byte reveal for this file, or have the owner settle this exact replacement.";

/// Why a proposal from a masked copy holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoProjectionHoldCause {
    /// The diff edits a sealed-file placeholder (CALL H).
    SealedFileEdited,
    /// The diff has no unique mapping onto the original (ASK E).
    ProjectionEditConflict,
}

impl RepoProjectionHoldCause {
    /// The engine reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealedFileEdited => SEALED_FILE_EDITED,
            Self::ProjectionEditConflict => PROJECTION_EDIT_CONFLICT,
        }
    }

    /// The one status line the candidate's optional detail shows.
    #[must_use]
    pub const fn status(self) -> &'static str {
        match self {
            Self::SealedFileEdited => SEALED_FILE_EDITED_STATUS,
            Self::ProjectionEditConflict => PROJECTION_EDIT_CONFLICT_STATUS,
        }
    }
}
