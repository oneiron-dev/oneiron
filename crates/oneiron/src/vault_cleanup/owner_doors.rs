//! The owner's cleanup doors for a transport. Each takes the authenticated
//! owner and rechecks that proof in the transaction that commits, so a
//! request queued behind a revocation changes nothing. The proof-free doors
//! beside them stay for a host that holds the vault as its own owner.

use super::proposals_archive::{accept_cleanup_proposal_in_txn, reject_cleanup_proposal_in_txn};
use super::retention::set_task_retention_days_in_txn;
use super::tripwire::set_cleanup_posture_in_txn;
use super::{CleanupAcceptOutcome, CleanupPosture};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;

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

    /// [`Self::restore_archived`], as `owner`.
    ///
    /// # Errors
    ///
    /// As [`Self::accept_cleanup_proposal_as`].
    pub fn restore_archived_as(&self, owner: &AuthenticatedOwner, entity: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.restore_archived_in_txn(txn, entity)
        })
    }
}
