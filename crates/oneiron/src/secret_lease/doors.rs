//! T0/T1/T2 Vault doors: inject, materialize, register, revoke, expire.

use std::path::Path;

use super::admission::admit_record_use;
use super::codec::{SECRET_LEASE, SECRET_LOCAL_REGISTRATION};
use super::files::write_secret_file;
use super::storage::{
    read_live_lease_in_txn, read_local_registration_in_txn, read_record_for_ref_in_txn,
    read_secret_lease_in_txn, read_value_for_ref_in_txn, stamp_secret_lease_in_txn,
    teardown_local_registration_in_txn, write_local_registration_in_txn, write_secret_lease_in_txn,
};
use super::types::{
    DoorInjectionReceipt, LocalRegistration, SecretLease, SecretLeaseMaterialization,
    SecretLeaseStatus, SecretTaintRef, StoredLocalRegistration, VaultInstant,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{CustodyTier, SecretBinding, SecretCustodyFloor};

use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// T0 door injection. Resolves `secret_ref`, admits `T0Doored` under
    /// the one admission rule, and runs `apply` INSIDE the door with the
    /// value. `apply` returns only `()`: the value cannot come back through
    /// the closure's return type, and the workspace receives only the
    /// [`DoorInjectionReceipt`]. The receipt carries no value bytes; the
    /// value is wrapped in [`Zeroizing`](zeroize::Zeroizing) for the door's own lifetime and
    /// scrubbed on drop.
    ///
    /// The door receipt is the return token only — the door CALLER
    /// (CSTDY-02's outbound path) stamps the durable egress receipt for its
    /// own send, and SECRET-04 attaches exhaust taint from
    /// [`DoorInjectionReceipt::taint_token`].
    pub fn inject_secret_at_door(
        &self,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &wtxn, secret_ref)?;
        self.inject_admitted(wtxn, &id, &rec, secret_ref, effector, apply)
    }

    /// [`Vault::inject_secret_at_door`] on one custody record named by its
    /// id, not by its live name: a handle names the record it was minted
    /// for, so a name re-registered since never reaches its door. A revoked
    /// or suspended record refuses as the name door does.
    pub(crate) fn inject_secret_record_at_door(
        &self,
        id: &EntityId,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        let rec =
            crate::secret_custody::read_secret_custody_admission_in_txn(&self.store, &wtxn, id)?
                .ok_or_else(|| {
                    Error::Secret(SecretError::SecretRefNotFound { name: id.to_hex() })
                })?;
        let secret_ref = rec.name.clone();
        self.inject_admitted(wtxn, id, &rec, &secret_ref, effector, apply)
    }

    /// The one T0 body both doors share: admission under the live floor and
    /// the door policy, the value read through the bound door, the write
    /// transaction released, then `apply`.
    fn inject_admitted(
        &self,
        wtxn: heed::RwTxn<'_>,
        id: &EntityId,
        rec: &crate::secret_custody::SecretCustodyAdmission,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(rec, effector, CustodyTier::T0Doored, &floor)?;
        crate::credential_door::admit_materialization_in_txn(&self.store, &wtxn, effector, None)?;
        let generation = rec.rotation_generation;
        let value = read_value_for_ref_in_txn(self, &wtxn, id, effector)?;
        // The value bytes are owned; nothing was written. Release the write
        // txn BEFORE running caller code — caller closures never execute
        // inside an LMDB write txn.
        drop(wtxn);
        apply(&value)?;
        Ok(DoorInjectionReceipt {
            secret_ref: secret_ref.to_owned(),
            effector: effector.to_owned(),
            injected_at: self.store.clock.now_recorded_at(),
            value_generation: generation,
            taint_token: vec![SecretTaintRef {
                secret_ref: secret_ref.to_owned(),
                generation,
            }],
        })
    }

    /// Whether [`Vault::inject_secret_at_door`] would release `secret_ref` to
    /// `effector` now: the same resolution, admission rule, custody floor,
    /// door policy and read grant on the binding the value door resolves,
    /// all read from the value-free admission projection. A host asks before
    /// it starts a call that will need the value, so a call the door would
    /// refuse is refused before it starts.
    pub fn check_secret_at_door(&self, secret_ref: &str, effector: &str) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let (_, rec) = read_record_for_ref_in_txn(&self.store, &txn, secret_ref)?;
        let floor = SecretCustodyFloor::resolve(&self.store, &txn)?;
        admit_record_use(&rec, effector, CustodyTier::T0Doored, &floor)?;
        crate::credential_door::admit_materialization_in_txn(&self.store, &txn, effector, None)?;
        if rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            Ok(())
        } else {
            Err(Error::Secret(SecretError::SecretBindingDenied {
                effector: effector.to_owned(),
                secret_ref: rec.name,
            }))
        }
    }

    /// T1 lease materialization. Admits `T1Leased` under the one admission
    /// rule, then writes the [`SecretLease`] row and its
    /// [`SecretMaterializationReceipt`](crate::secret_lease::SecretMaterializationReceipt) durable BEFORE the value returns —
    /// receipt-at-materialization (S3). One write txn carries both rows, so
    /// a failed receipt write leaves no lease row and returns no value (the
    /// `#[cfg(test)]` fault hook proves it). Expiry is lazy: the lease is
    /// expired from `expires_at` on, checked at use and by
    /// [`Vault::expire_secret_leases`].
    ///
    /// Unbounded: `expires_at` is `granted_at + ttl_secs` and nothing else.
    /// A caller whose authority ENDS at a known instant must use
    /// [`Vault::materialize_secret_lease_bounded`] instead, so the bound is
    /// enforced by the same clock that stamps the lease.
    pub fn materialize_secret_lease(
        &self,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
    ) -> Result<SecretLeaseMaterialization> {
        self.materialize_secret_lease_bounded(secret_ref, effector, ttl_secs, None)
    }

    /// [`Vault::materialize_secret_lease`] under an ABSOLUTE expiry bound.
    ///
    /// `not_after` is an absolute unix-seconds instant the minted lease may
    /// never outlive — the expiry of whatever authority bought it. A relative
    /// `ttl_secs` cannot carry that guarantee across the gap between a
    /// caller's authorization clock and the write transaction's own: the
    /// caller computes `ttl_secs` at its witnessed `now`, and this method
    /// stamps `granted_at` from a FRESH reading, so any advance between the
    /// two would push `granted_at + ttl_secs` past the authority's end. The
    /// bound closes that gap by construction:
    ///
    /// * `granted_at` and the bound check read the SAME clock reading inside
    ///   the one materializing write transaction, so no delay between
    ///   authorization and persistence can widen the ticket;
    /// * `expires_at` is `min(granted_at + ttl_secs, not_after)`, so the
    ///   lease dies with the authority even when the clock moved;
    /// * a reading at or past `not_after` means the authority's window closed
    ///   before the lease could be stamped, which fails closed — no lease
    ///   row, no receipt row, and no value returned.
    ///
    /// `not_after: None` is exactly [`Vault::materialize_secret_lease`]'s
    /// unbounded behaviour, unchanged for every existing caller.
    ///
    pub fn materialize_secret_lease_bounded(
        &self,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
        not_after: Option<u64>,
    ) -> Result<SecretLeaseMaterialization> {
        self.materialize_secret_lease_at(
            secret_ref,
            effector,
            ttl_secs,
            VaultInstant(self.store.clock.now_recorded_at()),
            not_after.map(VaultInstant),
        )
    }

    /// [`Vault::materialize_secret_lease_bounded`] under an instant that has
    /// already been WITNESSED, carried in as a [`VaultInstant`] rather than
    /// read here.
    ///
    /// One stamping operation under ONE reading: `now` dates `granted_at`,
    /// computes and clamps `expires_at`, and dates the materialization
    /// receipt, so the row, its receipt, and the bound check can never
    /// disagree about when the lease was minted.
    ///
    pub(super) fn materialize_secret_lease_at(
        &self,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
        now: VaultInstant,
        not_after: Option<VaultInstant>,
    ) -> Result<SecretLeaseMaterialization> {
        let mut wtxn = self.store.env.write_txn()?;
        let materialization = stamp_secret_lease_in_txn(
            self, &mut wtxn, secret_ref, effector, ttl_secs, now, not_after,
        )?;
        wtxn.commit()?;
        Ok(materialization)
    }

    /// T2 local registration under a live lease. The lease must be `Active`
    /// (a past-due lease is expired in place and denies); the target must
    /// be a manifest-declared path of the record (exact, file-granularity —
    /// the same granularity SECRET-03 excludes at); and `T2LocalRegistered`
    /// must admit under the one admission rule, re-resolved against the
    /// LIVE floor at registration time. The value re-materializes from the
    /// vault on every call (S4 recovery), the file is written before any
    /// row persists, and the lease climbs to `T2LocalRegistered`.
    pub fn register_secret_local(
        &self,
        lease_id: &EntityId,
        target_path: &Path,
        project_id: &str,
    ) -> Result<LocalRegistration> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut lease = match read_live_lease_in_txn(
            &self.store,
            &mut wtxn,
            lease_id,
            self.store.clock.now_recorded_at(),
        ) {
            Ok(lease) => lease,
            Err(error) => {
                // A lazy-expiry flip (and its T2 teardown) lands durable
                // even though the use denies: the vault's observed state
                // converges instead of re-discovering the expiry forever.
                wtxn.commit()?;
                return Err(error);
            }
        };
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &wtxn, &lease.secret_ref)?;
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(
            &rec,
            &lease.binding_effector,
            CustodyTier::T2LocalRegistered,
            &floor,
        )?;
        if !rec
            .declared_paths
            .iter()
            .any(|declared| Path::new(declared) == target_path)
        {
            return Err(Error::Secret(SecretError::SecretLeasePathNotDeclared {
                secret_ref: rec.name,
                path: target_path.display().to_string(),
            }));
        }
        // One registration row per lease (SOL-1920-02): a live registration
        // pins the lease to its path. A DIFFERENT declared path under the
        // same lease would overwrite the row and orphan the first plaintext
        // file beyond revoke/expiry — typed conflict; the caller mints a
        // fresh lease for a new path. Same-path re-materialization is the S4
        // recovery flow and stays admitted, into the registered file only.
        let registered = match read_local_registration_in_txn(&self.store, &wtxn, lease_id)? {
            Some(stored) if stored.registration.path.as_path() != target_path => {
                return Err(Error::Secret(SecretError::SecretLeasePathConflict {
                    lease_id: lease.lease_id,
                    registered_path: stored.registration.path.display().to_string(),
                    requested_path: target_path.display().to_string(),
                }));
            }
            Some(stored) => Some(stored.file_identity),
            None => None,
        };
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, &lease.binding_effector)?;
        // The file write lands before any row persists, under the T2
        // file-lifecycle policy (no-follow, no-clobber, owner-only before
        // the first byte, and a replace only into the registered file). The
        // returned guard removes a file THIS attempt created fresh if the row
        // write, the lease write, or the commit fails — nothing durable may
        // point at a file the vault cannot clean, and no plaintext may sit
        // untracked. A same-path replace is never the guard's to remove: the
        // live row still covers it.
        let guard = write_secret_file(target_path, &value, registered)?;
        let registration = LocalRegistration {
            lease_id: lease.lease_id,
            path: target_path.to_path_buf(),
            content_hash: *blake3::hash(&value).as_bytes(),
            project_id: project_id.to_owned(),
        };
        write_local_registration_in_txn(
            &self.store,
            &mut wtxn,
            &StoredLocalRegistration {
                registration: registration.clone(),
                file_identity: guard.identity(),
                removal_error: None,
                removal_attempted_at: None,
            },
        )?;
        lease.tier = CustodyTier::T2LocalRegistered;
        write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
        // A failed commit drops the guard armed: a fresh file is removed,
        // a replaced file stays under its live row.
        wtxn.commit()?;
        guard.disarm();
        Ok(registration)
    }

    /// Tears a lease down: flips the status to `Revoked`, revokes
    /// door-side use, and — for T2 — removes the registered local file
    /// (best-effort, recorded; see `teardown_local_registration_in_txn`).
    /// Revoking an already-`Revoked` lease is a no-op returning the row.
    /// `at` is the caller's clock for the teardown record (ARCH-0026: the
    /// engine owns no timers). Caller-held process memory is out of reach
    /// by construction — the ratified lease-scoped contract.
    pub fn revoke_secret_lease(&self, lease_id: &EntityId, at: u64) -> Result<SecretLease> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut lease) = read_secret_lease_in_txn(&self.store, &wtxn, lease_id)? else {
            return Err(Error::Secret(SecretError::SecretLeaseNotFound {
                lease_id: *lease_id,
            }));
        };
        if lease.status != SecretLeaseStatus::Revoked {
            lease.status = SecretLeaseStatus::Revoked;
            write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
            teardown_local_registration_in_txn(&self.store, &mut wtxn, lease_id, at)?;
        }
        wtxn.commit()?;
        Ok(lease)
    }

    /// The maintenance sweep: expires every `Active` lease whose
    /// `expires_at` has passed (`now >= expires_at`), tearing down its T2
    /// file with it, and returns how many leases expired. Lazy expiry is
    /// also checked at use; this sweep is the convergence path. No timers —
    /// the caller drives the cadence (ARCH-0026).
    pub fn expire_secret_leases(&self, now: u64) -> Result<usize> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut due = Vec::new();
        for (_, lease) in SECRET_LEASE.scan(&self.store, &wtxn)? {
            if lease.status == SecretLeaseStatus::Active && now >= lease.expires_at {
                due.push(lease);
            }
        }
        let mut expired = 0usize;
        for mut lease in due {
            lease.status = SecretLeaseStatus::Expired;
            write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
            teardown_local_registration_in_txn(&self.store, &mut wtxn, &lease.lease_id, now)?;
            expired += 1;
        }
        wtxn.commit()?;
        Ok(expired)
    }

    /// Retries, through the same teardown, the registrations a revoke or an
    /// expiry kept because their file could not be removed then: the oldest
    /// attempt first, at most `limit` a call. A registration whose lease is
    /// still `Active` is never touched, and a file that is not the one the
    /// vault wrote is never removed. Returns how many registrations went with
    /// their file and how many are still kept.
    pub(crate) fn retry_kept_secret_teardowns(&self, now: u64, limit: usize) -> Result<(u64, u64)> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut kept = Vec::new();
        for (_, stored) in SECRET_LOCAL_REGISTRATION.scan(&self.store, &wtxn)? {
            let Some(attempted_at) = stored.removal_attempted_at else {
                continue;
            };
            let lease_id = stored.registration.lease_id;
            let retired = read_secret_lease_in_txn(&self.store, &wtxn, &lease_id)?
                .is_none_or(|lease| lease.status != SecretLeaseStatus::Active);
            if retired {
                kept.push((attempted_at, lease_id));
            }
        }
        kept.sort_unstable();
        let mut removed = 0u64;
        for (_, lease_id) in kept.iter().take(limit) {
            teardown_local_registration_in_txn(&self.store, &mut wtxn, lease_id, now)?;
            if read_local_registration_in_txn(&self.store, &wtxn, lease_id)?.is_none() {
                removed += 1;
            }
        }
        wtxn.commit()?;
        let still_kept = u64::try_from(kept.len()).unwrap_or(u64::MAX) - removed;
        Ok((removed, still_kept))
    }
}
