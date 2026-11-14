//! The one rotation the engine runs on its own: a provider's refresh answer
//! stored in place of the grant a credential door read (RULING
//! MICROSOFT365-REFRESH-WRITEBACK, 14 Nov 07:00, B). Microsoft answers each
//! refresh with a newer refresh token, and the stored grant takes it, so the
//! owner's sign-in lasts as long as the connection is used.
//!
//! It changes no one's reach. The record keeps its name, bindings, class and
//! floor; only its value, generation and `rotated_at` move, through the
//! owner rotation's own value replace. The old value is wiped, and the
//! receipt names the cause `provider_refresh`.
//!
//! Every guard is read in the one write transaction that replaces the value.
//! A guard that does not hold writes nothing, and the caller drops the newer
//! grant. Microsoft does not revoke the older refresh token, so the stored
//! one still works.
//! - The record is the one the door read: the name still resolves to a live
//!   record at the generation the door read. A rotation, a revoke or another
//!   write-back since then leaves it as it is.
//! - It is Active, no admitted revoke names it and no erase fenced it, so an
//!   erase or revoke of the grant stops any further write-back.
//! - The owner stored it: not a cloud registration slot, no manifest, and
//!   bound with read to the effector the door read it through.
//! - It stays on this device. A portable record's value changes only by an
//!   owner act (RULING MICROSOFT365-WRITEBACK-PORTABLE = A).
//! - At most one write-back a day for each record (RULING
//!   MICROSOFT365-WRITEBACK-CHECK-STALE = C + B).
//!
//! A pack setup check that matched the record before the write-back takes
//! the record after it, in the same transaction (B): a routine refresh does
//! not make the owner's card read stale.

use super::RotationCause;
use super::RotationReceipt;
use super::owner_door::Held;
use crate::Vault;
use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{
    read_secret_custody_meta_in_txn, refuse_bindings_wider_than_live_floor,
    refuse_revoked_use_in_txn,
};
use crate::secret_lease::DoorInjectionReceipt;
use crate::secret_record::{SecretCustodyStatus, custody_portable, is_cloud_registration_slot};
use crate::store::FenceLookup;
use crate::store::secret_name_index::resolve_secret_ref_in_txn;
use zeroize::Zeroizing;

/// The shortest time between two write-backs of one record: Microsoft keeps
/// a refresh token for 90 days, and the Excel connection refreshes on every
/// call.
pub(crate) const PROVIDER_REFRESH_WRITE_BACK_INTERVAL_SECS: u64 = 24 * 60 * 60;

impl Vault {
    /// [`Vault::store_provider_refreshed_grant`] for a provider call that
    /// already ran, with the vault's clock: a write-back that fails is
    /// logged by the secret's name and dropped, and never becomes the call's
    /// error. Nothing happens without a successor.
    pub(crate) fn keep_provider_refreshed_grant(
        &self,
        door: &DoorInjectionReceipt,
        successor: Option<Zeroizing<Vec<u8>>>,
    ) {
        let Some(successor) = successor else {
            return;
        };
        let at = self.now_recorded_at();
        if let Err(error) = self.store_provider_refreshed_grant(door, &successor, at) {
            tracing::warn!(
                secret = %door.secret_ref,
                %error,
                "a provider's refreshed grant was not stored"
            );
        }
    }

    /// Stores `successor`, the grant a provider's refresh answer rewrote, in
    /// place of the value the door `door` read, when every guard of this
    /// module holds; `Ok(None)` when one does not, and nothing is written.
    /// `at` is the caller's clock (ARCH-0026).
    ///
    /// # Errors
    ///
    /// An empty `successor`; bindings wider than the live custody floor;
    /// the store's errors.
    pub(crate) fn store_provider_refreshed_grant(
        &self,
        door: &DoorInjectionReceipt,
        successor: &[u8],
        at: u64,
    ) -> Result<Option<RotationReceipt>> {
        if successor.is_empty() {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a provider refresh stores no empty grant",
            )));
        }
        if is_cloud_registration_slot(&door.secret_ref) {
            return Ok(None);
        }
        let mut wtxn = self.store.env.write_txn()?;
        let Some(id) = resolve_secret_ref_in_txn(&self.store, &wtxn, &door.secret_ref)? else {
            return Ok(None);
        };
        let Some(record) = read_secret_custody_meta_in_txn(&self.store, &wtxn, &id)? else {
            return Ok(None);
        };
        let mut held = Held(record);
        let rec = &mut held.0;
        if rec.status != SecretCustodyStatus::Active
            || rec.rotation_generation != door.value_generation
            || custody_portable(rec)
            || !rec.manifest_ref().is_empty()
            || !rec
                .binding_for(&door.effector)
                .is_some_and(|binding| binding.grants_read())
            || at
                < rec
                    .rotated_at
                    .unwrap_or(rec.registered_at)
                    .saturating_add(PROVIDER_REFRESH_WRITE_BACK_INTERVAL_SECS)
        {
            return Ok(None);
        }
        if self.store.credential_fence_in_txn(&wtxn, &id) != FenceLookup::Clear {
            return Ok(None);
        }
        match refuse_revoked_use_in_txn(self, &wtxn, &id, rec.class, &rec.name) {
            Ok(()) => {}
            Err(Error::Secret(SecretError::SecretCustodyNotActive { .. })) => return Ok(None),
            Err(error) => return Err(error),
        }
        refuse_bindings_wider_than_live_floor(&self.store, &wtxn, rec)?;
        let current = self.current_pack_checks_in_txn(&wtxn, &id)?;
        let receipt = self.replace_value_in_txn(
            &mut wtxn,
            &id,
            rec,
            successor,
            at,
            RotationCause::ProviderRefresh,
        )?;
        self.keep_pack_checks_current_in_txn(&mut wtxn, &id, receipt.to_generation, current)?;
        drop(held);
        wtxn.commit()?;
        Ok(Some(receipt))
    }
}
