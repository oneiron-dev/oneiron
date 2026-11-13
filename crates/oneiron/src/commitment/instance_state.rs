//! One commitment instance's joint state (FIX 22383).
//!
//! An instance acts (it wakes, is proposed, approved, reminded, lapsed or
//! fulfilled by its brief) only while the head of its status chain is an
//! active claim whose promise is open. A generic retraction closes the head's
//! claim and leaves the promise's status as it was, so an instance retracted
//! while open is withdrawn: it never acts again, its due phases go in the
//! retraction's own transaction, and it is given no fulfilled or lapsed
//! status it never reached.

use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

use super::{CommitmentRecord, CommitmentStatus, decode_commitment_claim};

/// The joint state of one commitment instance: the head of its status chain,
/// that head's claim lifecycle and its promise's status, read in one
/// transaction.
#[derive(Debug)]
pub(crate) enum CommitmentInstanceState {
    /// No commitment claim stands at the instance ref.
    Missing,
    /// The head is an active claim and its promise is open: the instance may
    /// act.
    Open(CommitmentRecord),
    /// The head is an active claim and its promise is inert: a signing
    /// document names it and is not yet signed. It does not act until the
    /// document completes and opens it.
    Inert(CommitmentRecord),
    /// The head's promise carries a terminal status.
    Closed(CommitmentRecord),
    /// The head's claim was closed while its promise was open (a generic
    /// retraction): the instance was withdrawn and acts no more.
    Withdrawn,
}

impl Vault {
    /// The joint state of `instance` in the caller's transaction.
    pub(crate) fn commitment_instance_state_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        instance: &EntityId,
    ) -> Result<CommitmentInstanceState> {
        let head = self.commitment_head_in_txn(txn, instance)?;
        let Some(body) = self.get_claim_in_txn(txn, &head)? else {
            return Ok(CommitmentInstanceState::Missing);
        };
        let Some(record) = decode_commitment_claim(&body)? else {
            return Ok(CommitmentInstanceState::Missing);
        };
        let active = body.lifecycle == ClaimLifecycleStatus::Active;
        Ok(match record.status {
            CommitmentStatus::Open if active => CommitmentInstanceState::Open(record),
            CommitmentStatus::Inert if active => CommitmentInstanceState::Inert(record),
            CommitmentStatus::Open | CommitmentStatus::Inert => CommitmentInstanceState::Withdrawn,
            CommitmentStatus::Fulfilled
            | CommitmentStatus::Released
            | CommitmentStatus::Lapsed
            | CommitmentStatus::Superseded => CommitmentInstanceState::Closed(record),
        })
    }

    /// [`Vault::commitment_instance_state_in_txn`] in its own read transaction.
    pub(crate) fn commitment_instance_state(
        &self,
        instance: &EntityId,
    ) -> Result<CommitmentInstanceState> {
        let txn = self.store.env.read_txn()?;
        self.commitment_instance_state_in_txn(&txn, instance)
    }

    /// Drops the due phases (Lead, Due and LifecycleDue) of a withdrawn
    /// `instance` in the caller's transaction, and returns whether it was
    /// withdrawn. Any other state writes nothing. The series membership row
    /// stays, so the withdrawn occurrence is never minted again.
    pub(crate) fn clear_withdrawn_commitment_due_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        instance: &EntityId,
    ) -> Result<bool> {
        if !matches!(
            self.commitment_instance_state_in_txn(&*wtxn, instance)?,
            CommitmentInstanceState::Withdrawn
        ) {
            return Ok(false);
        }
        self.store
            .commitment_due_clear_instance_phases_in_txn(wtxn, instance)?;
        Ok(true)
    }

    /// [`Vault::clear_withdrawn_commitment_due_in_txn`] in its own write
    /// transaction: the lapse sweep's repair of a withdrawn instance whose due
    /// phases outlived its retraction.
    pub(crate) fn clear_withdrawn_commitment_due(&self, instance: &EntityId) -> Result<bool> {
        self.with_write_txn_grouped(|wtxn| {
            self.clear_withdrawn_commitment_due_in_txn(wtxn, instance)
        })
    }
}
