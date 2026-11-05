//! Core half of `store::training_link`: its store-layer items live in `oneiron_store::training_link` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::training_link::*;

use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySubject, EntryState, LocalCustody,
    RetireCause, RetirementIntent, stage_retirement_in_txn,
};
use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

/// Requires every live generation of K of a restore's `plan` in `bound`,
/// the custody the image binds, so a side restore copies it and the copy
/// can still withdraw and purge its past codes. A K never minted, missing or
/// retired needs nothing.
pub(in crate::store) fn require_live_link_key(
    plan: &mut CustodyPlan,
    bound: &CustodyBinding,
) -> Result<()> {
    for (id, state) in LocalCustody::at(bound).census()? {
        if id.kind() == CustodyKind::TrainingLink && state == EntryState::Live {
            plan.require(&id)?;
        }
    }
    Ok(())
}

impl Store {
    /// Where K's slot at `generation` stands. No custody bound to this
    /// vault (a restore that brought none) reads as missing.
    ///
    /// # Errors
    /// Custody faults: a slot that cannot be read is no answer.
    pub(crate) fn training_link_slot(&self, generation: u32) -> Result<TrainingLinkSlot> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(TrainingLinkSlot::Missing);
        };
        let id = link_subject(custody.binding())?.at(u64::from(generation));
        Ok(match custody.state(&id)? {
            EntryState::Live => TrainingLinkSlot::Live,
            EntryState::Retired => TrainingLinkSlot::Retired,
            EntryState::Missing => TrainingLinkSlot::Missing,
        })
    }

    /// K at `generation`, minted in `wtxn` when custody holds none there
    /// yet, the binding pinned in the same transaction: the entry is
    /// published and synced before the writer that first relies on it
    /// commits. The caller decides that a mint is due: the vault's first
    /// training use, or a missing slot after a restore (FIX 5892), never a
    /// retired or unreadable one. A retry of an uncommitted writer finds the
    /// entry it published and uses it.
    ///
    /// # Errors
    /// An archived vault, whose custody is its replacement's, and custody
    /// faults.
    pub(crate) fn mint_training_link_key_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        generation: u32,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = link_subject(custody.binding())?.at(u64::from(generation));
        let secret = custody.get_or_create(&id)?;
        copy_key(secret.expose())
    }

    /// K at `generation`, read strictly: a retired, damaged or missing
    /// entry, or no custody at all, is an error, never a new key.
    ///
    /// # Errors
    /// K is not there to read.
    pub(crate) fn read_training_link_key(&self, generation: u32) -> Result<Zeroizing<[u8; 32]>> {
        let custody = self
            .core
            .key_custody
            .local()
            .ok_or_else(|| CustodyKind::TrainingLink.corrupt())?;
        let id = link_subject(custody.binding())?.at(u64::from(generation));
        let secret = custody.read(&id)?;
        copy_key(secret.expose())
    }

    /// Stages K's retirement as an erase's, through `generation` (every
    /// older one goes with it), in the writer that applies the last purge
    /// control's `removed` receipt. [`Self::finish_training_link_retirements`]
    /// carries it out after the commit.
    ///
    /// # Errors
    /// An archived vault, and storage faults.
    pub(crate) fn stage_training_link_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        generation: u32,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        // Unbound: no K was ever minted here.
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let intent = RetirementIntent {
            subject: link_subject(custody.binding())?,
            through: u64::from(generation),
            cause: RetireCause::Erase,
        };
        stage_retirement_in_txn(self, wtxn, &intent)
    }

    /// Completes K's staged retirement, including one an interrupted
    /// process left behind, once `ready`, its client's own rule, holds.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, the rule's error, and
    /// custody faults.
    pub(crate) fn finish_training_link_retirements(
        &self,
        ready: impl Fn(&RoTxn<'_>) -> Result<bool>,
    ) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::TrainingLink, |txn, _| ready(txn))
    }
}
