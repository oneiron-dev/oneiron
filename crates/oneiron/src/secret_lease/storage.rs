//! Txn row reads/writes, teardown, lazy expiry, and the one stamping body.

use std::fs;

use zeroize::Zeroizing;

use super::admission::admit_record_use;
use super::codec::{
    decode_local_registration_body, decode_secret_lease_body, encode_local_registration_body,
    encode_materialization_receipt_body, encode_secret_lease_body, lease_key, receipt_key,
    registration_key,
};
use super::types::{
    SecretLease, SecretLeaseMaterialization, SecretLeaseStatus, SecretMaterializationReceipt,
    StoredLocalRegistration, VaultInstant,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyTier, SecretCustodyAdmission, SecretCustodyFloor, read_secret_custody_admission_in_txn,
    resolve_secret_ref_in_txn,
};
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
    let Some(raw) = store.vault_meta.get(txn, &lease_key(lease_id))? else {
        return Ok(None);
    };
    decode_secret_lease_body(&raw).map(Some)
}

pub(crate) fn write_secret_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease: &SecretLease,
) -> Result<()> {
    let body = encode_secret_lease_body(lease)?;
    store
        .vault_meta
        .put(wtxn, &lease_key(&lease.lease_id), &body)?;
    Ok(())
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
        return Err(Error::SecretLeaseReceiptWriteFailed(
            "injected receipt-write failure",
        ));
    }
    let body = encode_materialization_receipt_body(receipt)?;
    store
        .vault_meta
        .put(wtxn, &receipt_key(&receipt.receipt_id), &body)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod receipt_fault_hook {
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
    pub(crate) fn arm_receipt_write_failure() {
        RECEIPT_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_receipt_write_failure() -> bool {
        RECEIPT_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

pub(super) fn read_local_registration_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    lease_id: &EntityId,
) -> Result<Option<StoredLocalRegistration>> {
    let Some(raw) = store.vault_meta.get(txn, &registration_key(lease_id))? else {
        return Ok(None);
    };
    decode_local_registration_body(&raw).map(Some)
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
    let body = encode_local_registration_body(stored)?;
    store.vault_meta.put(
        wtxn,
        &registration_key(&stored.registration.lease_id),
        &body,
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod registration_fault_hook {
    //! One-shot test-only fault injection on the local-registration write,
    //! proving the SOL-1920-03 file guard: a failed row write after the
    //! file lands removes the file the attempt created fresh.

    use std::cell::Cell;

    thread_local! {
        // One-shot, mirroring `receipt_fault_hook`.
        static REGISTRATION_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot registration-write failure on the current thread.
    pub(crate) fn arm_registration_write_failure() {
        REGISTRATION_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_registration_write_failure() -> bool {
        REGISTRATION_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

/// T2 teardown, shared by revoke and both expiry paths: removes the
/// registered file best-effort and records the outcome. The registration
/// row is DELETED only when the file is verifiably gone (removed, or
/// already absent); a failed removal retains the row with the error and
/// the attempt time recorded, so the path stays in SECRET-03's exclusion
/// set for as long as the file may still hold the value.
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
    let file_gone = match fs::remove_file(&stored.registration.path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            write_local_registration_in_txn(
                store,
                wtxn,
                &StoredLocalRegistration {
                    registration: stored.registration,
                    removal_error: Some(error.to_string()),
                    removal_attempted_at: Some(at),
                },
            )?;
            false
        }
    };
    if file_gone {
        store.vault_meta.delete(wtxn, &registration_key(lease_id))?;
    }
    Ok(())
}

/// Loads a lease for use: unknown id ⇒ [`Error::SecretLeaseNotFound`];
/// a past-due `Active` lease is expired in place (lazy expiry, its T2 file
/// torn down with it) and any non-`Active` status denies with
/// [`Error::SecretLeaseNotActive`]. A lease is expired from `expires_at`
/// on: `now >= expires_at`.
pub(super) fn read_live_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    now: u64,
) -> Result<SecretLease> {
    let Some(mut lease) = read_secret_lease_in_txn(store, wtxn, lease_id)? else {
        return Err(Error::SecretLeaseNotFound {
            lease_id: *lease_id,
        });
    };
    if lease.status == SecretLeaseStatus::Active && now >= lease.expires_at {
        lease.status = SecretLeaseStatus::Expired;
        write_secret_lease_in_txn(store, wtxn, &lease)?;
        teardown_local_registration_in_txn(store, wtxn, lease_id, now)?;
    }
    if lease.status != SecretLeaseStatus::Active {
        return Err(Error::SecretLeaseNotActive {
            lease_id: lease.lease_id,
            status: lease.status,
        });
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
        Error::SecretRefNotFound {
            name: secret_ref.to_owned(),
        }
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
    let value = read_value_for_ref_in_txn(vault, wtxn, &id, effector)?;
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
    let lease = SecretLease {
        lease_id: EntityId::now(),
        secret_ref: secret_ref.to_owned(),
        binding_effector: effector.to_owned(),
        tier: CustodyTier::T1Leased,
        granted_at: now,
        expires_at,
        status: SecretLeaseStatus::Active,
        materialization_receipt: EntityId::now(),
        value_generation: rec.rotation_generation,
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
    Ok(SecretLeaseMaterialization { lease, value })
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
