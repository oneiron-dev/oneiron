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

use super::claims::{RepoProjectionClaim, RepoProjectionClearance, RepoProjectionRecord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::GitOid;

/// CALL H: the reason code of a diff that edits a sealed-file placeholder.
pub(crate) const SEALED_FILE_EDITED: &str = "sealed_file_edited";

/// CALL H, exactly: the status line beside [`SEALED_FILE_EDITED`].
pub(crate) const SEALED_FILE_EDITED_STATUS: &str = "This diff edits a sealed-file placeholder. Grant real-byte reveal for this file, or have the \
     owner approve this exact replacement.";

/// ASK E: the reason code of a diff with no unique mapping onto the
/// original.
pub(crate) const PROJECTION_EDIT_CONFLICT: &str = "projection_edit_conflict";

/// CALL 2, exactly: the status line beside [`PROJECTION_EDIT_CONFLICT`].
pub(crate) const PROJECTION_EDIT_CONFLICT_STATUS: &str = "This diff does not map uniquely to the original file. Submit an exact or rebased proposal, \
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
pub(crate) struct RepoProjectionHeldFile {
    pub(crate) path: String,
    pub(crate) original: Option<GitOid>,
    pub(crate) proposed: Option<GitOid>,
    pub(crate) cause: RepoProjectionHoldCause,
}

/// The exact proposal a clearance is for: its candidate, its masked copy's
/// graph, its held files and the canonical target it would land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionHeldProposal {
    pub(crate) candidate: EntityId,
    pub(crate) graph: EntityId,
    pub(crate) files: Vec<RepoProjectionHeldFile>,
    pub(crate) target: Option<GitOid>,
}

impl RepoProjectionHeldProposal {
    /// The digest of the exact files `cause` holds: path, original and
    /// proposed blob of each, in path order. Ids only, never content.
    fn files_digest(&self, cause: RepoProjectionHoldCause) -> [u8; 32] {
        let mut files: Vec<&RepoProjectionHeldFile> = self
            .files
            .iter()
            .filter(|file| file.cause == cause)
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.repo_projection.held_files.v1");
        let mut part = |field: &[u8]| {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        };
        for file in files {
            part(file.path.as_bytes());
            part(file.original.as_ref().map_or("", GitOid::as_str).as_bytes());
            part(file.proposed.as_ref().map_or("", GitOid::as_str).as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Each cause a held file carries, once, sealed-file edits first.
    fn causes(&self) -> Vec<RepoProjectionHoldCause> {
        let mut causes: Vec<RepoProjectionHoldCause> =
            self.files.iter().map(|file| file.cause).collect();
        causes.sort_unstable();
        causes.dedup();
        causes
    }

    fn clearance(&self, cause: RepoProjectionHoldCause, owner: EntityId) -> RepoProjectionClaim {
        RepoProjectionClaim::of(
            self.graph,
            RepoProjectionRecord::Clearance(RepoProjectionClearance {
                candidate: self.candidate,
                cause: cause.as_str().to_owned(),
                files: self.files_digest(cause),
                target: self.target.clone(),
                owner,
            }),
        )
    }
}

/// The cause `proposal` still holds on, in `txn`, or `None` once every
/// cause is cleared: by `owner`'s recorded settlement of this exact
/// proposal (candidate, cause, file set and target), or for every held
/// file of the cause by `live_reveal`, the caller's check of a live
/// real-byte reveal grant covering that file for that recipient now. With
/// no unique target a conflict never clears by a reveal alone: it cannot
/// land without a target.
///
/// # Errors
/// A store failure, or `live_reveal`'s own.
pub(crate) fn require_projection_edit_clearance_in_txn<F>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    proposal: &RepoProjectionHeldProposal,
    owners: &[EntityId],
    mut live_reveal: F,
) -> Result<Option<RepoProjectionHoldCause>>
where
    F: FnMut(&RepoProjectionHeldFile) -> Result<bool>,
{
    for cause in proposal.causes() {
        let mut settled = false;
        for owner in owners {
            if proposal
                .clearance(cause, *owner)
                .stands_in_txn(vault, txn)?
            {
                settled = true;
                break;
            }
        }
        if settled {
            continue;
        }
        if proposal.target.is_none() {
            return Ok(Some(cause));
        }
        let mut revealed = true;
        for file in proposal.files.iter().filter(|file| file.cause == cause) {
            if !live_reveal(file)? {
                revealed = false;
                break;
            }
        }
        if !revealed {
            return Ok(Some(cause));
        }
    }
    Ok(None)
}

/// Records `owner`'s approval of exactly `proposal` for each cause it
/// holds, in the writer that settles it: the approval clears that
/// candidate's file set and target, and nothing else. Says whether any
/// record was new.
///
/// # Errors
/// A store failure.
pub(crate) fn record_projection_owner_clearance_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proposal: &RepoProjectionHeldProposal,
    owner: EntityId,
    at: u64,
) -> Result<bool> {
    let mut wrote = false;
    for cause in proposal.causes() {
        wrote |= proposal
            .clearance(cause, owner)
            .put_in_txn(vault, wtxn, at)?;
    }
    Ok(wrote)
}
