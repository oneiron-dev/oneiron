//! The owner's revoke on a custody request (WILL L04 row 04): its carrier
//! records it with no byte, and every replica that folds it holds the id as
//! terminal and settles it here, as the parent module's docs say.

use std::cell::Cell;

use super::super::doors::{read_secret_custody_admission_in_txn, resolve_secret_ref_in_txn};
use super::super::read_secret_custody_meta_in_txn;
use super::super::transition::{
    Enactment, custody_portable, drop_sealed_carrier_in_txn, holds_sealed_carrier_in_txn,
    write_custody_transition_in_txn,
};
use super::super::types::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use super::input::drop_inputs_for_in_txn;
use super::pending_revoke::{can_carry_in_txn, defer_revoke_in_txn};
use super::{CustodyKeptHere, SecretCustodyWork, enacted};
use crate::authority::{ActSurface, CustodyChange, CustodyRecipientPermits, OwnerWorkBody};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SecretError};
use crate::secret_rotation::{RevokeCause, holds_erasable_value_in_txn, revoke_custody_in_txn};
use crate::store::Store;
use crate::{EntityId, Vault};

impl Vault {
    /// Records the owner's revoke of the record `secret_ref` names for his
    /// other machines, in the revoke door's write transaction, after the
    /// record and its leases were revoked here, for `actor`, the live vault
    /// owner the door checked in it: a custody revoke request naming this
    /// install, its carrier, as executor (CALLS CUSTODY_EXECUTOR), its
    /// enacted result, then the revoked transition bound to the request. Its
    /// `seen` is the secret's custody revision here (CALLS
    /// CUSTODY_REVISION). Nothing is recorded, and the work says why the
    /// revoke stays here (FIX 4994), for a record that stays on its device.
    /// When this install cannot carry the act now, with no live machine
    /// profile or no install key loaded, the revoke stands here and its
    /// carry is kept pending, value-free, for the next pass that can sign
    /// (CALLS CUSTODY_REVOKE_PENDING_CARRY, FIX 4851).
    ///
    /// # Errors
    /// A name no record holds; the store's errors.
    pub(crate) fn carry_custody_revoke_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        secret_ref: &str,
        at: u64,
    ) -> Result<SecretCustodyWork> {
        let missing = || Error::CorruptedIndex("secret custody record for live name");
        let id = resolve_secret_ref_in_txn(&self.store, txn, secret_ref)?.ok_or_else(missing)?;
        let record = read_secret_custody_meta_in_txn(&self.store, txn, &id)?.ok_or_else(missing)?;
        if !custody_portable(&record) {
            return Ok(SecretCustodyWork::kept(CustodyKeptHere::DeviceLocal));
        }
        match self.carry_revoke_for_in_txn(txn, actor, surface, id, &record, at)? {
            Some(work) => Ok(work),
            None => defer_revoke_in_txn(
                self,
                txn,
                id,
                actor,
                surface,
                record.rotation_generation,
                at,
            ),
        }
    }

    /// Carries `actor`'s revoke of portable record `id`, held here as
    /// `record`, its value out: the request, its enacted result and the
    /// revoked transition signed at `at`, in `txn`. `None`, with nothing
    /// written, when this install cannot carry an owner act now.
    pub(super) fn carry_revoke_for_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        id: EntityId,
        record: &SecretCustodyRecord,
        at: u64,
    ) -> Result<Option<SecretCustodyWork>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !can_carry_in_txn(self, txn, &fold)? {
            return Ok(None);
        }
        let seen = fold.custody_work_revision(id);
        let work = OwnerWorkBody::Custody {
            change: CustodyChange::Revoke,
            generation: record.rotation_generation,
            input: None,
            holder: None,
            recipients: CustodyRecipientPermits::default(),
            pieces: None,
            authority: crate::authority::CustodyRequestAuthority::Install,
        };
        let receipt = self.record_owner_work_for_in_txn(txn, actor, surface, id, seen, work)?;
        let (Some(request), Some(executor)) = (receipt.request_entry(), receipt.executor) else {
            return Ok(Some(SecretCustodyWork::recorded(receipt)));
        };
        self.append_owner_work_result_in_txn(txn, request, executor, enacted(None))?;
        let enactment = Enactment {
            request,
            input: None,
            permits: &[],
        };
        write_custody_transition_in_txn(self, txn, id, record, enactment, at)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(Some(SecretCustodyWork::recorded(receipt.refreshed(&after))))
    }

    /// Settles every admitted custody revoke this vault has not met yet,
    /// byte-free, in one writer transaction: each portable record held under
    /// an id the fold holds terminal is revoked here with its leases, its
    /// value erased (CALLS CUSTODY_REVOKE_ERASE), a record revoked before
    /// that erase gives up the value it still holds (FIX 5272), and a
    /// carrier that still seals the value is dropped, even where this
    /// install holds the carrier alone. The owner work drain runs it after
    /// an authority catch-up and on the served tick; the fold is its only
    /// input, so nothing is queued and a restart loses nothing. Returns how
    /// many ids it settled.
    pub(crate) fn settle_revoked_custody(&self) -> Result<usize> {
        let due = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let mut due = Vec::new();
            for id in fold.custody_revoked_ids() {
                if revoke_due_in_txn(&self.store, &txn, &id)?
                    || holds_sealed_carrier_in_txn(self, &txn, &id)?
                {
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

/// The owner act an erase carries out, as the door that admitted the erase
/// holds it (FIX 11883): his proof, and where his request reached this
/// install (audit only). Each custody record the erase's side-row scrub
/// revokes is carried under it, as the revoke door carries his own revoke,
/// so the revoke goes everywhere his custody records live.
pub(crate) struct EraseOwnerAct<'a> {
    owner: &'a AuthenticatedOwner,
    surface: ActSurface,
    /// Whether a carry under it recorded custody work in the erase's
    /// writer, for the door to mirror once that commits.
    recorded: Cell<bool>,
}

impl<'a> EraseOwnerAct<'a> {
    /// The act of `owner`, whose request reached this install on `surface`.
    pub(crate) const fn new(owner: &'a AuthenticatedOwner, surface: ActSurface) -> Self {
        Self {
            owner,
            surface,
            recorded: Cell::new(false),
        }
    }
}

impl EraseOwnerAct<'_> {
    /// Carries the revoke of the record `secret_ref` names, made here in
    /// `txn` at `at`, to the owner's other machines under this act, as the
    /// revoke door carries his: at once when this install can sign, else
    /// kept pending (CALLS CUSTODY_REVOKE_PENDING_CARRY). A record that stays
    /// on its device is not carried. A proof that no longer holds the owner
    /// tier in `txn` carries nothing: the revoke stands here and the erase
    /// goes on.
    ///
    /// # Errors
    /// The store's errors.
    pub(crate) fn carry_revoke_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        secret_ref: &str,
        at: u64,
    ) -> Result<()> {
        let actor = match self.owner.revalidate_in_txn(vault, txn) {
            Ok(actor) => actor,
            Err(Error::Gate(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let custody =
            vault.carry_custody_revoke_in_txn(txn, actor, self.surface, secret_ref, at)?;
        if custody.work.is_some() {
            self.recorded.set(true);
        }
        Ok(())
    }

    /// Mirrors into the live windows the custody work the carries under this
    /// act recorded, once the erase committed, as the revoke door mirrors its
    /// own; with none recorded, nothing.
    pub(crate) fn mirror_after_commit(&self, vault: &Vault) {
        #[cfg(feature = "sync")]
        if self.recorded.get() {
            vault.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = vault;
    }
}

/// Whether this vault holds record `id` of the portable class and not yet
/// revoked, or revoked with value bytes a revoke erases still on it
/// ([`holds_erasable_value_in_txn`], FIX 5272): what an admitted revoke of
/// the id kills here. Its "this device only" dial does not shield it: the
/// owner revoked the secret itself.
fn revoke_due_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(held) = read_secret_custody_admission_in_txn(store, txn, id)? else {
        return Ok(false);
    };
    if held.class != CustodyClass::CustodyPortable {
        return Ok(false);
    }
    if held.status != SecretCustodyStatus::Revoked {
        return Ok(true);
    }
    let Some(record) = read_secret_custody_meta_in_txn(store, txn, id)? else {
        return Ok(false);
    };
    holds_erasable_value_in_txn(store, txn, id, &record)
}

/// Revokes record `id`, an id an admitted revoke names, here in `txn` with
/// every lease over it and its value erased, when this vault holds it of the
/// portable class and not yet revoked, or revoked with its value still at
/// rest; otherwise drops what this install still holds of it beyond the
/// record ([`drop_revoked_copies_in_txn`]). Returns whether it changed
/// anything.
pub(crate) fn settle_revoked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<bool> {
    if !revoke_due_in_txn(&vault.store, txn, id)? {
        return drop_revoked_copies_in_txn(vault, txn, id);
    }
    revoke_custody_in_txn(vault, txn, id, RevokeCause::Revoked, at)?;
    Ok(true)
}

/// Drops what this install holds of revoked record `id` beyond the record
/// (CALLS CUSTODY_REVOKE_ERASE): the carrier that still seals its value,
/// which the revoked carrier replaces where this install carries the act,
/// and every input kept for a request on it. Returns whether it dropped any.
pub(crate) fn drop_revoked_copies_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let carrier = drop_sealed_carrier_in_txn(vault, txn, id)?;
    Ok(drop_inputs_for_in_txn(vault, txn, id)? > 0 || carrier)
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
