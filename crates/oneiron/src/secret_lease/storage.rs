//! Txn row reads/writes, teardown, lazy expiry, and the one stamping body.

use zeroize::Zeroizing;

use super::admission::{admit_record_use, reveal_tier_admission};
use super::codec::{SECRET_LEASE, SECRET_LOCAL_REGISTRATION, SECRET_MATERIALIZATION_RECEIPT};
use super::files::remove_secret_file;
use super::types::{
    SecretLease, SecretLeaseMaterialization, SecretLeaseStatus, SecretMaterializationReceipt,
    StoredLocalRegistration, VaultInstant,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_custody::{
    CustodyTier, RevealAuthority, SecretCustodyAdmission, SecretCustodyFloor,
    read_secret_custody_admission_in_txn, resolve_secret_ref_in_txn, reveal_value_in_txn,
};
use crate::side_table::HexId;
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Row IO
// ---------------------------------------------------------------------------

pub(super) fn read_secret_lease_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    lease_id: &EntityId,
) -> Result<Option<SecretLease>> {
    SECRET_LEASE.get(store, txn, &HexId(*lease_id))
}

pub(crate) fn write_secret_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease: &SecretLease,
) -> Result<()> {
    SECRET_LEASE.put(store, wtxn, &HexId(lease.lease_id), lease)
}

/// Writes the materialization receipt row. S3: this lands durable BEFORE
/// the value returns from [`Vault::materialize_secret_lease`]; the
/// `#[cfg(test)]` fault hook fails the write so the done-means matrix can
/// prove no lease row and no value escape a failed receipt.
pub(super) fn write_materialization_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &SecretMaterializationReceipt,
) -> Result<()> {
    #[cfg(test)]
    if receipt_fault_hook::take_receipt_write_failure() {
        return Err(Error::Secret(SecretError::SecretLeaseReceiptWriteFailed(
            "injected receipt-write failure",
        )));
    }
    SECRET_MATERIALIZATION_RECEIPT.put(store, wtxn, &HexId(receipt.receipt_id), receipt)
}

#[cfg(test)]
pub(super) mod receipt_fault_hook {
    //! One-shot test-only fault injection on the materialization-receipt
    //! write, proving the S3 ordering: a failed receipt write leaves no
    //! lease row and returns no value.

    use std::cell::Cell;

    thread_local! {
        // One-shot: armed by `arm_receipt_write_failure`, consumed by the
        // next receipt write on this thread (the mirror-failure hook idiom
        // from `sync::lease`).
        static RECEIPT_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot receipt-write failure on the current thread.
    pub(in crate::secret_lease) fn arm_receipt_write_failure() {
        RECEIPT_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(super) fn take_receipt_write_failure() -> bool {
        RECEIPT_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

pub(super) fn read_local_registration_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    lease_id: &EntityId,
) -> Result<Option<StoredLocalRegistration>> {
    SECRET_LOCAL_REGISTRATION.get(store, txn, &HexId(*lease_id))
}

/// Writes the local-registration row. The `#[cfg(test)]` fault hook fails
/// the write so the T2 file guard can prove a post-write error removes the
/// file this attempt created fresh (SOL-1920-03).
pub(super) fn write_local_registration_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    stored: &StoredLocalRegistration,
) -> Result<()> {
    #[cfg(test)]
    if registration_fault_hook::take_registration_write_failure() {
        return Err(std::io::Error::other("injected registration-write failure").into());
    }
    SECRET_LOCAL_REGISTRATION.put(store, wtxn, &HexId(stored.registration.lease_id), stored)
}

#[cfg(test)]
pub(super) mod registration_fault_hook {
    //! One-shot test-only fault injection on the local-registration write,
    //! proving the SOL-1920-03 file guard: a failed row write after the
    //! file lands removes the file the attempt created fresh.

    use std::cell::Cell;

    thread_local! {
        // One-shot, mirroring `receipt_fault_hook`.
        static REGISTRATION_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot registration-write failure on the current thread.
    pub(in crate::secret_lease) fn arm_registration_write_failure() {
        REGISTRATION_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(super) fn take_registration_write_failure() -> bool {
        REGISTRATION_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

/// T2 teardown, shared by revoke and both expiry paths: removes the
/// registered file best-effort and records the outcome. The registration
/// row is DELETED only when the file is verifiably gone (removed, or
/// already absent); a failed removal, or a path now held by some other file,
/// retains the row with the error and the attempt time recorded, so the path
/// stays in SECRET-03's exclusion set for as long as the file may still hold
/// the value, and the other file is left untouched.
///
/// `pub(crate)` for SECRET-04's `revoke_secret` (ONE-1922), which revokes
/// every lease over a ref inside its own write transaction and must tear
/// down through this ONE body rather than a second, unmarked copy of it.
pub(crate) fn teardown_local_registration_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    at: u64,
) -> Result<()> {
    let Some(stored) = read_local_registration_in_txn(store, wtxn, lease_id)? else {
        return Ok(());
    };
    let file_gone = match remove_secret_file(&stored.registration.path, stored.file_identity) {
        Ok(()) => true,
        Err(error) => {
            write_local_registration_in_txn(
                store,
                wtxn,
                &StoredLocalRegistration {
                    removal_error: Some(error.to_string()),
                    removal_attempted_at: Some(at),
                    ..stored
                },
            )?;
            false
        }
    };
    if file_gone {
        SECRET_LOCAL_REGISTRATION.delete(store, wtxn, &HexId(*lease_id))?;
    }
    Ok(())
}

/// Loads a lease for use: unknown id ⇒ [`SecretError::SecretLeaseNotFound`](crate::error::SecretError::SecretLeaseNotFound);
/// a past-due `Active` lease is expired in place (lazy expiry, its T2 file
/// torn down with it) and any non-`Active` status denies with
/// [`SecretError::SecretLeaseNotActive`](crate::error::SecretError::SecretLeaseNotActive). A lease is expired from `expires_at`
/// on: `now >= expires_at`.
pub(super) fn read_live_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    now: u64,
) -> Result<SecretLease> {
    let Some(mut lease) = read_secret_lease_in_txn(store, wtxn, lease_id)? else {
        return Err(Error::Secret(SecretError::SecretLeaseNotFound {
            lease_id: *lease_id,
        }));
    };
    if lease.status == SecretLeaseStatus::Active && now >= lease.expires_at {
        lease.status = SecretLeaseStatus::Expired;
        write_secret_lease_in_txn(store, wtxn, &lease)?;
        teardown_local_registration_in_txn(store, wtxn, lease_id, now)?;
    }
    if lease.status != SecretLeaseStatus::Active {
        return Err(Error::Secret(SecretError::SecretLeaseNotActive {
            lease_id: lease.lease_id,
            status: lease.status,
        }));
    }
    Ok(lease)
}

/// Resolves a live secret name to its admission projection inside an
/// existing txn, for doors that already hold one. The projection is the
/// value-less read (SOL-1920-04): admission never materializes the value;
/// the ONE plaintext decode is the bound value door's own read.
pub(super) fn read_record_for_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    secret_ref: &str,
) -> Result<(EntityId, SecretCustodyAdmission)> {
    let id = resolve_secret_ref_in_txn(store, txn, secret_ref)?.ok_or_else(|| {
        Error::Secret(SecretError::SecretRefNotFound {
            name: secret_ref.to_owned(),
        })
    })?;
    let rec = read_secret_custody_admission_in_txn(store, txn, &id)?
        .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
    Ok((id, rec))
}

/// The ONE stamping body, under a write transaction its CALLER owns.
///
/// Everything a T1 materialization does except opening and committing that
/// transaction lives here, exactly once: the record read, the custody floor
/// resolved under this same transaction, the one admission rule, the value read
/// through the bound value door, the bound arms, and the receipt-before-lease
/// row order. Both entries below funnel through it, so composing over the
/// landed materialization never grows a second, unmarked path to a mint — and
/// the door's extra in-transaction admission is a check ADDED in front of this
/// body, never a re-implementation of it.
///
/// Module-private on purpose: the caller-owned transaction is the whole reason
/// this exists, and a `pub(crate)` version of it would be exactly the raw
/// `(effector, ttl_secs, now, not_after)` mint path the typed admission
/// removed.
///
/// The bound arms are unchanged: `expires_at` is `min(now + ttl_secs,
/// not_after)`, and a reading at or past `not_after` fails closed. Returning an
/// error here writes nothing the caller can commit — the caller drops its write
/// transaction uncommitted — so no lease row, no receipt row, and no value
/// escape a bound this materialization can no longer honour.
pub(super) fn stamp_secret_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    secret_ref: &str,
    effector: &str,
    ttl_secs: u64,
    now: VaultInstant,
    not_after: Option<VaultInstant>,
) -> Result<SecretLeaseMaterialization> {
    let (id, rec) = read_record_for_ref_in_txn(&vault.store, wtxn, secret_ref)?;
    let floor = SecretCustodyFloor::resolve(&vault.store, wtxn)?;
    admit_record_use(&rec, effector, CustodyTier::T1Leased, &floor)?;
    // ONE instant stamps `granted_at`, dates the receipt, and answers the
    // bound. Nothing between authorization and here can move them apart.
    let now = now.secs();
    let expires_at = match not_after.map(VaultInstant::secs) {
        // The window closed before the lease could be stamped. Returning
        // here leaves the caller's write txn uncommitted, so no row and no
        // value escape a bound this materialization can no longer honour.
        Some(bound) if now >= bound => {
            return Err(Error::InvariantViolation(
                "secret lease expiry bound elapsed before materialization stamped the lease",
            ));
        }
        Some(bound) => now.saturating_add(ttl_secs).min(bound),
        None => now.saturating_add(ttl_secs),
    };
    // The dial caps actual exposure, not the caller's pre-bound request. A
    // shorter live not_after may make a larger requested TTL safe; both the
    // bound and this recheck happen under the committing writer, before the
    // value read or either durable row write.
    crate::credential_door::admit_materialization_in_txn(
        &vault.store,
        wtxn,
        effector,
        Some(expires_at - now),
    )?;
    let value = read_value_for_ref_in_txn(vault, wtxn, &id, effector)?;
    let lease = write_t1_lease_rows_in_txn(
        vault,
        wtxn,
        secret_ref,
        effector,
        now,
        expires_at,
        rec.rotation_generation,
    )?;
    Ok(SecretLeaseMaterialization { lease, value })
}

/// The T1 lease a granted reveal is (OF-560, ARCH-0069 #reveal-check): the
/// value leaves the vault once, to the model connection `authority` names,
/// in the receipt-before-lease order every materialization keeps.
///
/// A reveal holds no binding (a masked secret has none), so the binding rule
/// of [`stamp_secret_lease_in_txn`] does not apply. What admits it is the
/// consent the reveal door settled in this same transaction, which only that
/// door can carry here as a [`RevealAuthority`], and the reveal admission,
/// read again under this transaction against the live floor.
pub(crate) fn stamp_reveal_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    authority: &RevealAuthority,
    ttl_secs: u64,
) -> Result<SecretLeaseMaterialization> {
    let rec = read_secret_custody_admission_in_txn(&vault.store, wtxn, authority.secret())?
        .ok_or_else(|| {
            Error::Secret(SecretError::SecretRefNotFound {
                name: authority.handle().to_owned(),
            })
        })?;
    if rec.class != authority.class() {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "the secret's custody class changed since its reveal was asked",
        )));
    }
    let floor = SecretCustodyFloor::resolve(&vault.store, wtxn)?;
    reveal_tier_admission(&rec, &floor)?;
    let now = VaultInstant(vault.store.clock.now_recorded_at()).secs();
    let expires_at = now.saturating_add(ttl_secs);
    crate::credential_door::admit_materialization_in_txn(
        &vault.store,
        wtxn,
        authority.effector(),
        Some(ttl_secs),
    )?;
    let value = reveal_value_in_txn(&vault.store, wtxn, authority)?;
    let lease = write_t1_lease_rows_in_txn(
        vault,
        wtxn,
        &rec.name,
        authority.effector(),
        now,
        expires_at,
        rec.rotation_generation,
    )?;
    Ok(SecretLeaseMaterialization { lease, value })
}

/// The rows every T1 materialization writes once its value is read: the
/// materialization receipt, then the lease, then the expiry wake.
fn write_t1_lease_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    secret_ref: &str,
    effector: &str,
    now: u64,
    expires_at: u64,
    value_generation: u32,
) -> Result<SecretLease> {
    let lease = SecretLease {
        lease_id: vault.store.clock.entity_id()?,
        secret_ref: secret_ref.to_owned(),
        binding_effector: effector.to_owned(),
        tier: CustodyTier::T1Leased,
        granted_at: now,
        expires_at,
        status: SecretLeaseStatus::Active,
        materialization_receipt: vault.store.clock.entity_id()?,
        value_generation,
    };
    let receipt = SecretMaterializationReceipt {
        receipt_id: lease.materialization_receipt,
        secret_ref: lease.secret_ref.clone(),
        effector: lease.binding_effector.clone(),
        tier: lease.tier,
        lease_id: lease.lease_id,
        materialized_at: now,
        value_generation: lease.value_generation,
    };
    write_materialization_receipt_in_txn(&vault.store, wtxn, &receipt)?;
    write_secret_lease_in_txn(&vault.store, wtxn, &lease)?;
    // A vault that is not running wakes to expire the lease and remove its file.
    crate::housekeeping::note_wake_in_txn(
        &vault.store,
        wtxn,
        crate::housekeeping::HousekeepingSweep::SecretLeaseExpiry,
        expires_at,
    )?;
    Ok(lease)
}

/// Reads the value bytes through the ONE bound value door (ONE-1919), for
/// a record already admitted at `requested` tier.
pub(super) fn read_value_for_ref_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    effector: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let value = vault
        .get_secret_value_in_txn(txn, id, effector)?
        .ok_or(Error::CorruptedIndex("secret custody value for live name"))?;
    Ok(Zeroizing::new(value))
}
