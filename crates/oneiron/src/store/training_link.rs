//! The training link key's custody client (TRAINING-LINK = C, TL-2): K, the
//! one key the vault's publisher training codes are made under
//! (`feedback::conversation_training::link`).
//!
//! K is one subject per vault: kind `TrainingLink`, an empty item, one fixed
//! generation. It is minted in the writer that first needs it, which pins
//! the custody binding in the same transaction, and read strictly after. It
//! sits in the custody head's host-readable compartment, wrapped to the
//! recovery root when one is pinned and to the vault data key's custody
//! subkey, so a restore with either brings it back; a side restore carries
//! it while it is live. It retires only by an erase's durable intent, staged
//! in the writer that applies the last purge control's `removed` receipt and
//! finished after that commit, under its client's own readiness rule. It is
//! never rotated: a new K would orphan every past code from withdrawal and
//! erase.

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySubject, EntryState, LocalCustody,
    RetireCause, RetirementIntent, stage_retirement_in_txn,
};

/// K's one generation.
const LINK_GENERATION: u64 = 0;

/// K's subject in `binding`'s custody: a singleton, its item empty.
pub(in crate::store) fn link_subject(binding: &CustodyBinding) -> Result<CustodySubject> {
    binding.subject(CustodyKind::TrainingLink, &[])
}

/// Requires K of a restore's `plan` while it is live in `bound`, the
/// custody the image binds, so a side restore copies it and the copy can
/// still withdraw and purge its past codes. A K never minted, or retired,
/// needs nothing.
pub(in crate::store) fn require_live_link_key(
    plan: &mut CustodyPlan,
    bound: &CustodyBinding,
) -> Result<()> {
    if cfg!(not(unix)) {
        // No exterior custody exists here, so no K can either.
        return Ok(());
    }
    let id = link_subject(bound)?.at(LINK_GENERATION);
    if LocalCustody::at(bound).state(&id)? == EntryState::Live {
        plan.require(&id)?;
    }
    Ok(())
}

/// K's bytes, copied out of a custody secret: exactly 32.
fn copy_key(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    if secret.len() != key.len() {
        return Err(CustodyKind::TrainingLink.corrupt());
    }
    key.copy_from_slice(secret);
    Ok(key)
}

impl Store {
    /// K, minted in `wtxn` when custody holds none yet, the binding pinned in
    /// the same transaction: the entry is published and synced before the
    /// writer that first relies on it commits. The caller decides that this
    /// is the vault's first training use; once it recorded that, it reads K
    /// with [`Self::read_training_link_key`] and never mints again.
    ///
    /// # Errors
    /// An archived vault, whose custody is its replacement's, and custody
    /// faults.
    pub(crate) fn mint_training_link_key_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let secret =
            custody.get_or_create(&link_subject(custody.binding())?.at(LINK_GENERATION))?;
        copy_key(secret.expose())
    }

    /// K, read strictly: a retired, damaged or missing entry, or no custody
    /// at all, is an error, never a new key.
    ///
    /// # Errors
    /// K is not there to read.
    pub(crate) fn read_training_link_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let custody = self
            .core
            .key_custody
            .local()
            .ok_or_else(|| CustodyKind::TrainingLink.corrupt())?;
        let secret = custody.read(&link_subject(custody.binding())?.at(LINK_GENERATION))?;
        copy_key(secret.expose())
    }

    /// Stages K's retirement as an erase's, in the writer that applies the
    /// last purge control's `removed` receipt.
    /// [`Self::finish_training_link_retirements`] carries it out after the
    /// commit.
    ///
    /// # Errors
    /// An archived vault, and storage faults.
    pub(crate) fn stage_training_link_retirement_in_txn(&self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so no K can either.
            return Ok(());
        }
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        // Unbound: no K was ever minted here.
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let intent = RetirementIntent {
            subject: link_subject(custody.binding())?,
            through: LINK_GENERATION,
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
