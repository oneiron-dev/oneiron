//! Core half of `origin::secret_projection::clearance`: its store-layer items live in `oneiron_store::origin::secret_projection::clearance` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the queue, settlement and landing seams call it in 2b-ii-B"
)]

pub(crate) use oneiron_store::origin::secret_projection::clearance::*;

use super::claims::{RepoProjectionClaim, RepoProjectionClearance, RepoProjectionRecord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::GitOid;
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

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
