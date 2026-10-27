//! A projected candidate's clearance (FIX 7608 slice 2b-ii-B2, CALL H,
//! ASK E, CHANGED 4): the one adapter every landing seam asks (candidate
//! intake, the no-review enqueue in both its checks, stack readiness and
//! final admission, each not-yet-effected stack member and the received
//! files' effect) and the owner's settlement records into.
//!
//! An ordinary candidate answers `None` with no graph or grant read. A
//! projected one answers its uncleared typed cause: `sealed_file_edited`
//! or `projection_edit_conflict`, cleared only by the owner's settlement
//! of this exact replacement (its clearance record) or a live matching
//! reveal grant for the recipient its push proved (FIX 10271), read only
//! when no settlement clears it. A projected source that no longer stands, or a candidate with
//! no canonical target, holds as a conflict: never ordinary-clear. The
//! hold joins the existing queue path; nothing here adds a human wait, and
//! a vault with no review policy lands a cleared candidate on green.

use heed::RoTxn;

use super::super::document_candidate_types::CodePushCandidate;
use super::projected::RepoProjectedCandidatePins;
use super::projected_join::receive_operation_in_txn;
use super::projected_reveal::ProjectedRevealCheck;
use super::projected_source::require_projected_candidate_source_in_txn;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::origin::secret_projection::clearance::{
    PROJECTION_EDIT_CONFLICT, RepoProjectionHeldFile, RepoProjectionHeldProposal,
    RepoProjectionHoldCause, SEALED_FILE_EDITED, require_projection_edit_clearance_in_txn,
};
use crate::{EntityId, Vault};

impl Vault {
    /// The attached candidate `candidate` among the push `provenance`'s
    /// refs, its projection pins kept, in `txn`.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_candidate_attached_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<CodePushCandidate>> {
        Ok(self
            .received_candidate_row_in_txn(txn, provenance, candidate)?
            .and_then(|row| row.candidate))
    }

    /// The uncleared projection cause holding `candidate`, in `txn`; `None`
    /// for an ordinary candidate and for a cleared projected one.
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn projected_candidate_clearance_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<RepoProjectionHoldCause>> {
        let Some(attached) = self.received_candidate_attached_in_txn(txn, provenance, candidate)?
        else {
            return Ok(None);
        };
        let Some(pins) = &attached.projected else {
            return Ok(None);
        };
        let operation = receive_operation_in_txn(self, txn, provenance)?;
        let stands = match operation {
            Some(operation) => {
                require_projected_candidate_source_in_txn(self, txn, pins, candidate, operation)?
            }
            None => false,
        };
        if !stands || pins.canonical_target_tree.is_none() {
            return Ok(Some(RepoProjectionHoldCause::ProjectionEditConflict));
        }
        let held = held_proposal(candidate, pins)?;
        if held.files.is_empty() {
            return Ok(None);
        }
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        // The push's recipient is read only once a file needs a reveal.
        let mut reveal: Option<Option<ProjectedRevealCheck>> = None;
        let live_reveal = |file: &RepoProjectionHeldFile| -> Result<bool> {
            if reveal.is_none() {
                reveal = Some(match operation {
                    Some(operation) => {
                        self.projected_reveal_check_in_txn(txn, &held.graph, &operation)?
                    }
                    None => None,
                });
            }
            match reveal.as_ref().and_then(Option::as_ref) {
                Some(check) => check.covers_in_txn(self, txn, &file.path, file.original.as_ref()),
                None => Ok(false),
            }
        };
        require_projection_edit_clearance_in_txn(self, txn, &held, &owners, live_reveal)
    }

    /// The held proposal `candidate`'s pins name (its candidate, copy,
    /// exact held files and canonical target), for the owner's settlement
    /// of this exact replacement; `None` for an ordinary candidate and for
    /// a projected one no cause holds.
    ///
    /// # Errors
    /// A store failure, or a pin that does not parse.
    pub(crate) fn held_projected_proposal_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<RepoProjectionHeldProposal>> {
        let Some(attached) = self.received_candidate_attached_in_txn(txn, provenance, candidate)?
        else {
            return Ok(None);
        };
        let Some(pins) = &attached.projected else {
            return Ok(None);
        };
        let held = held_proposal(candidate, pins)?;
        Ok((!held.files.is_empty()).then_some(held))
    }
}

/// The status text a candidate's saved projection hold shows (FIX 9237):
/// the cause's own ruled text; `None` for any other hold.
pub(crate) fn projection_hold_detail(candidate: &CodePushCandidate) -> Option<String> {
    candidate.projected.as_ref()?;
    let reason = candidate.hold.as_ref()?.reason.as_str();
    let cause = match reason {
        SEALED_FILE_EDITED => RepoProjectionHoldCause::SealedFileEdited,
        PROJECTION_EDIT_CONFLICT => RepoProjectionHoldCause::ProjectionEditConflict,
        _ => return None,
    };
    Some(cause.status().to_owned())
}

/// The held proposal of `candidate` its pins name.
fn held_proposal(
    candidate: EntityId,
    pins: &RepoProjectedCandidatePins,
) -> Result<RepoProjectionHeldProposal> {
    let parse = |oid: &Option<String>| -> Result<Option<GitOid>> {
        oid.as_ref()
            .map(|oid| GitOid::parse_hex(oid.clone()))
            .transpose()
    };
    let mut files = Vec::new();
    for file in &pins.files {
        let Some(cause) = file.cause else {
            continue;
        };
        files.push(RepoProjectionHeldFile {
            path: file.path.clone(),
            original: parse(&file.original_blob)?,
            proposed: parse(&file.canonical_blob)?,
            cause,
        });
    }
    Ok(RepoProjectionHeldProposal {
        candidate,
        graph: pins.graph,
        files,
        target: parse(&pins.canonical_target_tree)?,
    })
}
