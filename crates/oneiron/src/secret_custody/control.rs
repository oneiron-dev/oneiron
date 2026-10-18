//! Custody control on the shared owner-work request (WILL L04 row 04): the
//! owner's revoke of a portable secret reaches every replica as main-log
//! metadata, with no byte.
//!
//! The revoke door records a custody revoke request naming this install,
//! its carrier, as executor, and in the same writer transaction revokes the
//! record and its leases here and appends the enacted result
//! ([`Vault::revoke_secret_as_owner`]). Every replica that folds the request
//! holds its id as terminal (`AuthorityFold::custody_revoked`): after an
//! authority catch-up and on the served tick it revokes a portable record it
//! holds under that id, with its leases (`Vault::settle_revoked_custody`); a
//! custody transition received for the id is refused in its committing
//! transaction, a value read or a lease refuses, and an archive restore
//! skips it. An id this vault never held stays absent: its knowledge is the
//! fold's, never an empty record. Nothing recalls an export or a use made
//! before the revoke arrived.
//!
//! An active change (register, rotate, rewrap) keeps today's path until its
//! producers land: the selector names its holder, and the pickup leaves it
//! pending unless its id is terminal.

use zeroize::Zeroize;

use super::doors::read_secret_custody_admission_in_txn;
use super::transition::custody_portable;
use super::types::{CustodyClass, SecretCustodyStatus};
use crate::authority::{
    ActSurface, AuthorityFold, CustodyChange, OwnerWorkBody, OwnerWorkOutcome, OwnerWorkRefusal,
    OwnerWorkRequest,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SecretError};
use crate::secret_rotation::RotationReceipt;
use crate::store::Store;
use crate::world_keys::{OwnerWorkReceipt, OwnerWorkUnassigned};
use crate::{EntityId, Vault};

/// Which install a custody request names to do its work (CALLS
/// CUSTODY_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyExecutor {
    /// An active change goes to the holder it names, a linked install whose
    /// proof key stands here: never elected, and no takeover. A revoke goes
    /// to the install that records it, its carrier.
    ExplicitHolderOrRevokeCarrier,
}

const CUSTODY_EXECUTOR: CustodyExecutor = CustodyExecutor::ExplicitHolderOrRevokeCarrier;

/// What a custody request's enacted result claims (CALLS
/// CUSTODY_COMPLETION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCompletion {
    /// Its executor committed the change here, with the result in the same
    /// commit: for a revoke, the record and its leases revoked here. Never
    /// that every replica holds it: replication is the sync's.
    CommitNotDelivery,
}

const CUSTODY_COMPLETION: CustodyCompletion = CustodyCompletion::CommitNotDelivery;

/// The install a custody request names as executor (CALLS
/// CUSTODY_EXECUTOR), or why none can be named.
pub(crate) fn custody_work_executor(
    fold: &AuthorityFold,
    change: CustodyChange,
    holder: Option<EntityId>,
    recorder: EntityId,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    match (CUSTODY_EXECUTOR, change) {
        // The one exception to the shared rule that the recorder is never
        // named while another install could do the work: a revoke needs no
        // byte, so the carrier that records it enacts it in the same commit.
        (CustodyExecutor::ExplicitHolderOrRevokeCarrier, CustodyChange::Revoke) => Ok(recorder),
        (
            CustodyExecutor::ExplicitHolderOrRevokeCarrier,
            CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap,
        ) => holder
            .filter(|holder| fold.machine_proof_key(*holder).is_some())
            .ok_or(OwnerWorkUnassigned::NoCustodyHolder),
    }
}

/// The outcome an executor's result records once its custody change is
/// committed (CALLS CUSTODY_COMPLETION).
fn enacted() -> OwnerWorkOutcome {
    match CUSTODY_COMPLETION {
        CustodyCompletion::CommitNotDelivery => OwnerWorkOutcome::Enacted,
    }
}

/// What the owner's revoke of a secret did: the rotation receipt of the
/// revoke here, and the shared receipt of the revoke recorded for his other
/// machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevoked {
    /// The record and every lease over it, revoked here.
    pub rotation: RotationReceipt,
    /// The custody revoke this install carried and enacted in the same
    /// commit. "Enacted" says it committed here, never that every replica
    /// holds it yet (CALLS CUSTODY_COMPLETION). `None` when nothing was
    /// recorded: the record stays on this device (device bound, cross-vault
    /// or "this device only"), or this install has no live machine profile
    /// to carry the owner's act, so no other machine learns of it from here.
    pub work: Option<OwnerWorkReceipt>,
}

impl Vault {
    /// Records the owner's revoke of the record `secret_ref` names for his
    /// other machines, in the revoke door's write transaction, after the
    /// record and its leases were revoked here: a custody revoke request
    /// naming this install, its carrier, as executor (CALLS
    /// CUSTODY_EXECUTOR), then its enacted result. Its `seen` is the
    /// secret's custody revision here (CALLS CUSTODY_REVISION). `None`, and
    /// nothing recorded, for a record that stays on this device or when this
    /// install cannot carry the act.
    pub(crate) fn carry_custody_revoke_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        secret_ref: &str,
    ) -> Result<Option<OwnerWorkReceipt>> {
        let Some(id) = super::resolve_secret_ref_in_txn(&self.store, txn, secret_ref)? else {
            return Ok(None);
        };
        let Some(mut record) = super::read_secret_custody_in_txn(&self.store, txn, &id)? else {
            return Ok(None);
        };
        record.value_bytes.zeroize();
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !custody_portable(&record) || self.owner_work_carrier_in_txn(txn, &fold)?.is_none() {
            return Ok(None);
        }
        let seen = fold.custody_work_revision(id);
        let work = OwnerWorkBody::Custody {
            change: CustodyChange::Revoke,
            generation: record.rotation_generation,
            input: None,
            holder: None,
            recipients: Vec::new(),
        };
        let receipt = self.record_owner_work_in_txn(txn, owner, surface, id, seen, work)?;
        let (Some(request), Some(executor)) = (receipt.request_entry(), receipt.executor) else {
            return Ok(Some(receipt));
        };
        self.append_owner_work_result_in_txn(txn, request, executor, enacted())?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(Some(receipt.refreshed(&after)))
    }

    /// The pickup's arm for a custody request naming this install. A revoke
    /// is settled here, byte-free, and answered enacted: it is terminal from
    /// its admission (CALLS CUSTODY_CONCURRENT_ACTIVE), so its executor never
    /// refuses it. An active change whose secret an admitted revoke names is
    /// refused as stale; any other stays pending (`None`) until its
    /// producers and executor land.
    pub(crate) fn custody_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        change: CustodyChange,
    ) -> Result<Option<OwnerWorkOutcome>> {
        let id = request.act.target;
        Ok(match change {
            CustodyChange::Revoke => {
                let at = self.instant_in_txn(txn)?.secs();
                settle_revoked_in_txn(self, txn, &id, at)?;
                Some(enacted())
            }
            CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap => fold
                .custody_revoked(&id)
                .then_some(OwnerWorkOutcome::Refused {
                    reason: OwnerWorkRefusal::StaleRevision,
                }),
        })
    }

    /// Settles every admitted custody revoke this vault has not met yet,
    /// byte-free, in one writer transaction: each portable record held under
    /// an id the fold holds terminal is revoked here with its leases. The
    /// owner work drain runs it after an authority catch-up and on the
    /// served tick; the fold is its only input, so nothing is queued and a
    /// restart loses nothing. Returns how many records it revoked.
    pub(crate) fn settle_revoked_custody(&self) -> Result<usize> {
        let due = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let mut due = Vec::new();
            for id in fold.custody_revoked_ids() {
                if revoke_due_in_txn(&self.store, &txn, &id)? {
                    due.push(id);
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            let at = self.instant_in_txn(txn)?.secs();
            let mut settled = 0;
            for id in &due {
                if settle_revoked_in_txn(self, txn, id, at)? {
                    settled += 1;
                }
            }
            Ok(settled)
        })
    }
}

/// Whether this vault holds record `id` of the portable class and not yet
/// revoked: what an admitted revoke of the id kills here. Its "this device
/// only" dial does not shield it: the owner revoked the secret itself.
fn revoke_due_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(
        read_secret_custody_admission_in_txn(store, txn, id)?.is_some_and(|held| {
            held.class == CustodyClass::CustodyPortable
                && held.status != SecretCustodyStatus::Revoked
        }),
    )
}

/// Revokes record `id`, an id an admitted revoke names, here in `txn` with
/// every lease over it, when this vault holds it of the portable class and
/// not yet revoked. Returns whether it did.
pub(crate) fn settle_revoked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<bool> {
    if !revoke_due_in_txn(&vault.store, txn, id)? {
        return Ok(false);
    }
    crate::secret_rotation::revoke_custody_in_txn(vault, txn, id, at)?;
    Ok(true)
}

/// Whether an admitted custody revoke names record `id` in `txn`'s fold:
/// terminal for it here (CALLS CUSTODY_CONCURRENT_ACTIVE), settled here yet
/// or not.
pub(crate) fn custody_revoked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(vault
        .authority_view_readonly_in_txn(txn)?
        .custody_revoked(id))
}

/// Refuses a use of the record `id` of class `class`, named `name`, once an
/// admitted custody revoke names it, though this vault has not settled it
/// yet: the value door, a reveal's lease and the door check read it in their
/// own transaction.
pub(crate) fn refuse_revoked_use_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    class: CustodyClass,
    name: &str,
) -> Result<()> {
    if class == CustodyClass::CustodyPortable && custody_revoked_in_txn(vault, txn, id)? {
        return Err(Error::Secret(SecretError::SecretCustodyNotActive {
            name: name.to_owned(),
        }));
    }
    Ok(())
}
