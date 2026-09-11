//! T0/T1/T2 Vault doors: inject, materialize, register, revoke, expire.

use std::path::Path;

use super::admission::admit_record_use;
use super::codec::decode_secret_lease_body;
use super::files::write_secret_file;
use super::storage::{
    read_live_lease_in_txn, read_local_registration_in_txn, read_record_for_ref_in_txn,
    read_secret_lease_in_txn, read_value_for_ref_in_txn, stamp_secret_lease_in_txn,
    teardown_local_registration_in_txn, write_local_registration_in_txn, write_secret_lease_in_txn,
};
use super::types::{
    DoorInjectionReceipt, LocalRegistration, SECRET_LEASE_KEY_PREFIX, SecretLease,
    SecretLeaseMaterialization, SecretLeaseStatus, SecretTaintRef, StoredLocalRegistration,
    VaultInstant,
};
use crate::credential_door::{AdmittedLease, DoorResult};
use crate::entity_id::EntityId;
use crate::error::SecretError;
use crate::error::{Error, Result};
use crate::secret_custody::{CustodyTier, SecretCustodyFloor};
use crate::unix_seconds_now;
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
    /// value is wrapped in [`Zeroizing`] for the door's own lifetime and
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
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(&rec, effector, CustodyTier::T0Doored, &floor)?;
        let generation = rec.rotation_generation;
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, effector)?;
        // The value bytes are owned; nothing was written. Release the write
        // txn BEFORE running caller code — caller closures never execute
        // inside an LMDB write txn.
        drop(wtxn);
        apply(&value)?;
        Ok(DoorInjectionReceipt {
            secret_ref: secret_ref.to_owned(),
            effector: effector.to_owned(),
            injected_at: unix_seconds_now(),
            value_generation: generation,
            taint_token: vec![SecretTaintRef {
                secret_ref: secret_ref.to_owned(),
                generation,
            }],
        })
    }

    /// T1 lease materialization. Admits `T1Leased` under the one admission
    /// rule, then writes the [`SecretLease`] row and its
    /// [`SecretMaterializationReceipt`] durable BEFORE the value returns —
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
    /// This wrapper is the API BOUNDARY, and the only place an external
    /// absolute second count becomes a `VaultInstant` bound. The wall
    /// reading it has always stamped stays exactly what it was, so every
    /// current non-door caller keeps its behaviour unchanged. The credential
    /// door does NOT come through here: it carries its whole admission into
    /// `Vault::materialize_admitted_lease` instead, so nothing a caller chose
    /// can date, scope, or size a door-issued lease.
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
            VaultInstant(unix_seconds_now()),
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
    /// PRIVATE to this module, and that is a load-bearing fact rather than
    /// tidiness. This is the raw shape — a bare effector string, a bare
    /// `ttl_secs`, a bare instant — and while the credential door could still
    /// name it, the door had two ways to reach a mint: this one, and the typed
    /// admission. "Exactly one admission shape reaches the stamp" is only true
    /// if the other shape is unreachable, so the door cannot see this at all
    /// any more. What remains is the wall-clock wrapper above, whose behaviour
    /// every existing non-door caller depends on and which is unchanged.
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

    /// The credential door's materialization: ONE admitted lease in, one
    /// stamped lease out, and the door's own admission taken AGAIN inside the
    /// transaction that stamps it.
    ///
    /// [`AdmittedLease`] is the whole argument list because it is the whole
    /// admission — the proved effector, the named secret, the TTL a ceiling
    /// admitted, the absolute instant the buying authority dies at, and the
    /// single witnessed reading all of it was decided under. There is no raw
    /// `max_lease_ttl_secs`, no caller-supplied effector set, and no second
    /// `now` to disagree with the first.
    ///
    /// The order here is the point of the whole step:
    ///
    /// 1. open the write transaction that will stamp the lease;
    /// 2. RE-RESOLVE the door dial under THAT transaction and refuse on any
    ///    disagreement with what the door admitted
    ///    ([`AdmittedLease::reaffirm_in_txn`]) — before the record is read,
    ///    before the custody floor is resolved, before a value byte is touched;
    /// 3. stamp through the one shared body, which resolves the custody floor
    ///    and runs the one admission rule under this same transaction;
    /// 4. commit.
    ///
    /// Previously (2) happened in a SEPARATE read transaction the door opened
    /// earlier, so the dial that admitted a request was never the dial the row
    /// committed under, and a dial narrowed in between still minted at the
    /// stale wide reading. Now the check and the commit are one atomic act: a
    /// refusal at (2) returns with the write transaction dropped uncommitted,
    /// leaving no lease row, no receipt row, and no value.
    ///
    /// No caller closure runs inside this transaction — there is none to run.
    /// T1 hands the value back to the caller after the commit; it is T0 that
    /// takes a closure, and T0 keeps its own drop-then-apply shape.
    pub(crate) fn materialize_admitted_lease(
        &self,
        admitted: &AdmittedLease,
    ) -> DoorResult<SecretLeaseMaterialization> {
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        admitted.reaffirm_in_txn(&self.store, &wtxn)?;
        let materialization = stamp_secret_lease_in_txn(
            self,
            &mut wtxn,
            admitted.secret_ref(),
            admitted.effector(),
            admitted.ttl_secs(),
            admitted.instant(),
            Some(admitted.not_after()),
        )?;
        wtxn.commit().map_err(Error::from)?;
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
        let mut lease =
            match read_live_lease_in_txn(&self.store, &mut wtxn, lease_id, unix_seconds_now()) {
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
        // fresh lease for a new path. Same-path re-materialization
        // (`replace`) is the S4 recovery flow and stays admitted.
        let replace = match read_local_registration_in_txn(&self.store, &wtxn, lease_id)? {
            Some(stored) if stored.registration.path.as_path() != target_path => {
                return Err(Error::Secret(SecretError::SecretLeasePathConflict {
                    lease_id: lease.lease_id,
                    registered_path: stored.registration.path.display().to_string(),
                    requested_path: target_path.display().to_string(),
                }));
            }
            Some(_) => true,
            None => false,
        };
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, &lease.binding_effector)?;
        // The file write lands before any row persists, under the T2
        // file-lifecycle policy (no-follow, no-clobber, owner-only before
        // the first byte). The returned guard removes a file THIS attempt
        // created fresh if the row write, the lease write, or the commit
        // fails — nothing durable may point at a file the vault cannot
        // clean, and no plaintext may sit untracked. A same-path replace is
        // never the guard's to remove: the live row still covers it.
        let guard = write_secret_file(target_path, &value, replace)?;
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
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&wtxn, SECRET_LEASE_KEY_PREFIX.as_bytes())?
        {
            let (_, raw) = entry?;
            let lease = decode_secret_lease_body(&raw)?;
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
}
