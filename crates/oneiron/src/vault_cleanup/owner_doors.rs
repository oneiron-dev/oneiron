//! The owner's cleanup doors for a transport. Each takes the authenticated
//! owner and rechecks that proof in the transaction that commits, so a
//! request queued behind a revocation changes nothing. The proof-free doors
//! beside them stay for a host that holds the vault as its own owner.
//!
//! What the owner brings back here, one entry or a whole run, he keeps: the
//! entry is marked at its revision and no cleanup arm takes that revision
//! again. A re-mention or a returning file restores without that mark.

use super::attempt_retention::{keep_attempt_in_txn, restore_archived_attempt_in_txn};
use super::marks::keep_record_in_txn;
use super::proposal_review::{Decided, decide_cleanup_proposal_in_txn};
use super::proposals_archive::{accept_cleanup_proposal_in_txn, reject_cleanup_proposal_in_txn};
use super::retention::set_task_retention_days_in_txn;
use super::run_revert::revert_cleanup_run_in_txn;
use super::tripwire::set_cleanup_posture_in_txn;
use super::{
    CleanupAcceptOutcome, CleanupDecideRequest, CleanupDecideView, CleanupPosture,
    CleanupRunRevertAnswer,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::MemoryResult;

impl Vault {
    /// [`accept_cleanup_proposal`](super::accept_cleanup_proposal), as `owner`.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds; otherwise the proof-free door's errors.
    pub fn accept_cleanup_proposal_as(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &EntityId,
    ) -> Result<CleanupAcceptOutcome> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            accept_cleanup_proposal_in_txn(self, txn, proposal)
        })
    }

    /// [`reject_cleanup_proposal`](super::reject_cleanup_proposal), as `owner`.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn reject_cleanup_proposal_as(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &EntityId,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            reject_cleanup_proposal_in_txn(self, txn, proposal)
        })
    }

    /// Decides one open cleanup proposal slot by slot, as `owner` (FIX
    /// 1758): a complete verdict, one Accept or Reject for every slot the
    /// review lists, committed once. Accepted slots are re-checked and
    /// archived as a whole accept does; rejected ones archive nothing and are
    /// recorded as rejected. A verdict that accepts nothing records no
    /// digest, as a whole reject. `expected_revision`, when sent, binds the
    /// decision to the review it names.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a verdict that is not one choice per slot or a
    /// malformed revision; `INVALID_STATE` when the review changed since
    /// `expected_revision`; `NOT_FOUND` when the proposal is no longer open;
    /// a lapsed owner proof and storage errors as
    /// [`Self::accept_cleanup_proposal_as`].
    pub fn decide_cleanup_proposal_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &CleanupDecideRequest,
    ) -> MemoryResult<CleanupDecideView> {
        let decided = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            decide_cleanup_proposal_in_txn(self, txn, input)
        });
        Decided::answer(decided, &input.proposal)
    }

    /// [`set_cleanup_posture`](super::set_cleanup_posture), as `owner`. The
    /// automatic posture stays refused while its rollout blockers are open.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn set_cleanup_posture_as(
        &self,
        owner: &AuthenticatedOwner,
        posture: CleanupPosture,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            set_cleanup_posture_in_txn(self, txn, posture)
        })
    }

    /// [`Self::set_task_retention_days`], as `owner`.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn set_task_retention_days_as(
        &self,
        owner: &AuthenticatedOwner,
        days: Option<u32>,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            set_task_retention_days_in_txn(self, txn, days)
        })
    }

    /// [`Self::restore_archived`], as `owner`. The owner keeps the record at
    /// its revision, and a TASK's archived attempts at their queue rows: no
    /// cleanup arm archives them again until they change (FIX 7518).
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn restore_archived_as(&self, owner: &AuthenticatedOwner, entity: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.restore_archived_kept_in_txn(txn, entity)?;
            keep_record_in_txn(self, txn, entity)
        })
    }

    /// [`Self::restore_archived_attempt`], as `owner`. The owner keeps the
    /// attempt at its exact queue row: retention does not archive those bytes
    /// again.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn restore_archived_attempt_as(
        &self,
        owner: &AuthenticatedOwner,
        attempt: AttemptId,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            restore_archived_attempt_in_txn(self, txn, attempt)?;
            keep_attempt_in_txn(self, txn, attempt)
        })
    }

    /// Reverts one whole cleanup run, named by its attempt id, as `owner`.
    ///
    /// Only the marks that run wrote are lifted, each entry in a savepoint of
    /// this write, and each restored entry is kept at its revision. An entry
    /// changed since the run answers why and stays as it is; a delete or an
    /// erase is never undone, and no entry refuses the run. The first answer
    /// is stored on the run's row, and a repeat returns it.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`]; a run row, snapshot or stored
    /// answer that does not read is
    /// [`Error::CorruptedIndex`](crate::error::Error::CorruptedIndex).
    pub fn revert_cleanup_run_as(
        &self,
        owner: &AuthenticatedOwner,
        attempt: AttemptId,
    ) -> Result<CleanupRunRevertAnswer> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            revert_cleanup_run_in_txn(self, txn, attempt)
        })
    }
}
