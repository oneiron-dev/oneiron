//! The owner's revoke on a custody request (WILL L04 row 04): its carrier
//! records it with no byte, and every replica that folds it holds the id as
//! terminal and settles it here, as the parent module's docs say.

use zeroize::Zeroize;

use super::super::doors::read_secret_custody_admission_in_txn;
use super::super::transition::{Enactment, custody_portable, write_custody_transition_in_txn};
use super::super::types::{CustodyClass, SecretCustodyStatus};
use super::enacted;
use crate::authority::{ActSurface, CustodyChange, OwnerWorkBody};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SecretError};
use crate::store::Store;
use crate::world_keys::OwnerWorkReceipt;
use crate::{EntityId, Vault};

impl Vault {
    /// Records the owner's revoke of the record `secret_ref` names for his
    /// other machines, in the revoke door's write transaction, after the
    /// record and its leases were revoked here: a custody revoke request
    /// naming this install, its carrier, as executor (CALLS
    /// CUSTODY_EXECUTOR), its enacted result, then the revoked transition
    /// bound to the request. Its `seen` is the secret's custody revision here
    /// (CALLS CUSTODY_REVISION). `None`, and nothing recorded, for a record
    /// that stays on this device or when this install cannot carry the act.
    pub(crate) fn carry_custody_revoke_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        secret_ref: &str,
        at: u64,
    ) -> Result<Option<OwnerWorkReceipt>> {
        let Some(id) = super::super::resolve_secret_ref_in_txn(&self.store, txn, secret_ref)?
        else {
            return Ok(None);
        };
        let Some(mut record) = super::super::read_secret_custody_in_txn(&self.store, txn, &id)?
        else {
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
        let enactment = Enactment {
            request,
            input: None,
            permits: &[],
        };
        write_custody_transition_in_txn(self, txn, id, &record, enactment, at)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(Some(receipt.refreshed(&after)))
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
/// yet: the value door, a reveal's lease, the door check, a rotation and a
/// binding read it in their own transaction.
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
