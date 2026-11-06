//! Core half of `store::checkpoint_payload`: its store-layer items live in `oneiron_store::checkpoint_payload` and are
//! re-exported here; the items below stay in the engine.

#![allow(dead_code, reason = "the strict live-key read waits on callers")]

pub(crate) use oneiron_store::checkpoint_payload::*;

use self::instance::{Lifecycle, PayloadInstance};
use crate::error::{Error, Result, StoreError};
use crate::side_table::SideKey;
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySubject, LocalCustody, Requirement,
    retirement_in_txn,
};
use crate::store::restore_admission::Rejected;
use crate::store::restore_admission::RestoreAdmissionReason;
use heed::RwTxn;
use oneiron_crypto::Purpose;
use zeroize::Zeroizing;

pub(crate) mod capture;
pub(crate) mod instance;
pub(crate) mod loro;
pub(crate) mod retirement;
pub(crate) mod rows;

impl Store {
    /// The leaf keys a capture seals `instances` under, in order, each minted
    /// while unpublished: the binding is pinned in `wtxn` with them, and a
    /// leaf is synced and its mint journaled (KS-4) before `wtxn` may commit
    /// anything sealed under it. The caller holds the custody read guard
    /// ([`crate::store::Store::custody_snapshot`]'s) from before `wtxn`
    /// opened until its last seal. Refused for an archived vault, whose
    /// custody is its replacement's, for an incarnation that is not active,
    /// and for a generation whose retirement is staged: nothing new is sealed
    /// under a leaf being destroyed, and a retired leaf is never minted again.
    pub(crate) fn checkpoint_payload_keys_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        instances: &[PayloadInstance],
    ) -> Result<Vec<Zeroizing<[u8; 32]>>> {
        ensure_enabled()?;
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let mut keys = Vec::with_capacity(instances.len());
        for instance in instances {
            if instance.lifecycle != Lifecycle::Active {
                return Err(retiring());
            }
            let subject = instance.item.subject(custody.binding())?;
            if retirement_in_txn(self, &*wtxn, &subject)?
                .is_some_and(|intent| intent.through >= instance.generation)
            {
                return Err(retiring());
            }
            let secret = custody.get_or_create(&subject.at(instance.generation))?;
            keys.push(leaf_key(secret.expose())?);
        }
        Ok(keys)
    }

    /// The leaf key of a live compartment in this vault's own custody, read
    /// strictly: a retired, damaged or missing leaf refuses, and so does a
    /// vault that never published one. The caller holds the custody read
    /// guard, or a [`crate::store::Store::custody_snapshot`], from before its
    /// LMDB snapshot until its last open, so no finisher destroys the leaf in
    /// between.
    pub(crate) fn checkpoint_payload_key(
        &self,
        item: &PayloadItem,
        generation: u64,
    ) -> Result<Zeroizing<[u8; 32]>> {
        ensure_enabled()?;
        let custody = self.core.key_custody.local().ok_or_else(corrupt)?;
        read_key(custody, item, generation)
    }
}

/// The leaf key of a live compartment in `custody` (a restore's source),
/// read strictly, under the guard its caller holds.
pub(crate) fn read_key(
    custody: LocalCustody<'_>,
    item: &PayloadItem,
    generation: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    ensure_enabled()?;
    let subject = item.subject(custody.binding())?;
    leaf_key(custody.read(&subject.at(generation))?.expose())
}

/// What a restore needs of each compartment `required` names (its item and
/// generation, from the image's manifest), recorded in the one plan the
/// restore's claim keys use, so its fork copies these leaves as well. Each
/// answer stands alone, in order: a live leaf opens; a retired one's rows are
/// dropped and recorded as erased; a refusal (a missing leaf, or no source
/// binding, each `custody_key_missing`) is the caller's to weigh under KS-4's
/// restore rules, and never stops the census of the others.
pub(crate) fn require_all(
    plan: &mut CustodyPlan,
    required: &[(PayloadItem, u64)],
) -> Result<Vec<std::result::Result<Requirement, Rejected>>> {
    ensure_enabled()?;
    Ok(required
        .iter()
        .map(|(item, generation)| {
            let source = plan.source().ok_or_else(custody_missing)?;
            let subject = item.subject(source)?;
            plan.require_rejected(&subject.at(*generation))
        })
        .collect())
}

/// What a restore opens each compartment `required` names with, in order,
/// through `plan`, the one plan its claim keys use ([`require_all`]). A
/// missing leaf refuses, as KS-4's lost custody does, `custody_key_missing`:
/// an image supplies a binding, never a key (ARCH-0038, a restore needs the
/// key custody).
///
/// # Errors
///
/// A missing leaf or source binding (`custody_key_missing`), a leaf that
/// does not read, and custody faults, each typed by its kind.
pub(crate) fn compartment_access(
    plan: &mut CustodyPlan,
    required: &[(PayloadItem, u64)],
) -> std::result::Result<Vec<CompartmentAccess>, Rejected> {
    let answers = require_all(plan, required)?;
    let source = plan.source().cloned();
    required
        .iter()
        .zip(answers)
        .map(|((item, generation), answer)| match answer? {
            Requirement::Retired => Ok(CompartmentAccess::Retired),
            Requirement::Live => {
                let binding = source.as_ref().ok_or_else(custody_missing)?;
                let key = read_key(LocalCustody::at(binding), item, *generation)?;
                Ok(CompartmentAccess::Open(key))
            }
        })
        .collect()
}
