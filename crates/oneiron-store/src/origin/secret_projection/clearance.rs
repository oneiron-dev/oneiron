//! The two typed holds a proposal from a masked copy can carry, and what
//! clears each (FIX 7608 slice 2b-ii-A; CALL H, ASK E).
//!
//! A push from a masked copy is received and kept as it is; its translated
//! proposal joins the vault's existing landing path (LandOnGreen when no
//! review policy is set). Only a proposal whose diff edits a sealed-file
//! placeholder ([`SEALED_FILE_EDITED`]) or has no unique mapping onto the
//! original ([`PROJECTION_EDIT_CONFLICT`]) holds, with its typed cause and
//! one status line, never a new human gate, timeout or queue. A cause
//! clears only for its own candidate, file set and target: by a live
//! real-byte reveal grant that matches it now (never an old delivery
//! receipt), or by the owner's settlement of that exact replacement,
//! recorded in the same writer as the approval. A clearance never covers a
//! later proposal.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the queue, settlement and landing seams call it in 2b-ii-B"
)]

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::git_wire::ids::GitOid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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

/// One held file of a projected proposal, as a clearance names it: its
/// path, the ORIGINAL blob and the proposed canonical blob, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionHeldFile {
    pub path: String,
    pub original: Option<GitOid>,
    pub proposed: Option<GitOid>,
    pub cause: RepoProjectionHoldCause,
}
