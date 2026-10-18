//! FIX 4313: minting and renewing a secret grant.
//!
//! One committing writer stamps a grant. A door (T0) grant is the grant row
//! alone. A leased (T1) grant composes the one stamping body
//! ([`stamp_secret_lease_in_txn`]) with its grant row; a local (T2) grant adds
//! the T2 registration in the same writer. The value then leaves the vault
//! only to the T1 host destination ([`SecretHostDelivery`]) or the T2 file,
//! never into what the call answers.

use std::path::Path;

use zeroize::Zeroizing;

use super::admission::admit_record_use;
use super::codec::SECRET_LOCAL_REGISTRATION;
use super::delivery::{SecretHostDelivery, no_destination};
use super::files::SecretFileGuard;
use super::grant::{
    SECRET_GRANT_DEFAULT_TTL_SECS, SECRET_GRANT_MAX_TTL_SECS, SECRET_GRANT_RENEW_HANDOVER,
    SecretGrantCaller, SecretGrantHandover, SecretGrantHolder, SecretGrantMinted,
    SecretGrantStatus, SecretGrantTarget, SecretLeaseGrant, grant_mismatch, live_held_grant_in_txn,
    read_grant_in_txn, read_held_grant_in_txn, retire_grant_in_txn, write_grant_in_txn,
};
use super::storage::{read_local_registration_in_txn, stamp_secret_lease_in_txn};
use super::types::{FileIdentity, LocalRegistration, SecretLease, VaultInstant};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::outbound_consent::connector_call_effector;
use crate::secret_custody::{
    CustodyTier, SECRET_USE_OPERATIONS, SecretBinding, SecretCustodyAdmission, SecretCustodyFloor,
    SecretCustodyStatus, handle_record_in_txn, read_secret_custody_admission_in_txn,
    resolve_secret_ref_in_txn,
};
use crate::side_table::HexId;
use crate::store::Store;
use crate::vault::Vault;

/// A grant stamped in its writer, before the commit.
struct Stamped {
    grant: SecretLeaseGrant,
    lease: Option<SecretLease>,
    registration: Option<LocalRegistration>,
    /// A T1 grant's bytes, for its destination once the writer commits.
    value: Option<Zeroizing<Vec<u8>>>,
    /// A T2 grant's file guard, disarmed once the writer commits.
    guard: Option<SecretFileGuard>,
}

/// What one grant is stamped for.
struct GrantAsk<'a> {
    holder: SecretGrantHolder,
    custody: EntityId,
    rec: &'a SecretCustodyAdmission,
    effector: &'a str,
    target: SecretGrantTarget,
    ttl_secs: u64,
    not_after: Option<u64>,
    /// The file a renewed T2 grant's registration already holds.
    registered: Option<FileIdentity>,
}

impl Vault {
    /// Mints a grant on the secret `handle` names for `caller`, to `target`.
    ///
    /// The target fixes the rung and the effector: a `self.use` operation or
    /// a connector is a door (T0) grant, a redemption right with no lease and
    /// no buffer; a host destination is a T1 grant whose bytes go to the
    /// destination `delivery` registered for the caller's run, and only
    /// there; a declared local file is a T2 grant. The record's binding for
    /// the effector must grant read and admit the rung under the live floor.
    /// `ttl_secs` is cut to [`super::SECRET_GRANT_MAX_TTL_SECS`] (`None`
    /// takes the default) and `not_after` bounds it absolutely, as
    /// [`Vault::materialize_secret_lease_bounded`] does. Grant, lease,
    /// materialization receipt and T2 registration commit in one writer
    /// before any byte leaves the vault. Answers metadata only.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`] for an operation the table does not
    /// hold or a connector no call routes to;
    /// [`SecretError::SecretHostDeliveryRefused`] for a destination the run's
    /// host did not register, or a delivery it refused (the grant and its
    /// lease are then revoked); the handle, record, binding, floor, door
    /// policy and T2 path refusals.
    pub fn mint_secret_grant(
        &self,
        caller: &SecretGrantCaller,
        handle: &str,
        target: SecretGrantTarget,
        ttl_secs: Option<u64>,
        not_after: Option<u64>,
        delivery: &mut dyn SecretHostDelivery,
    ) -> Result<SecretGrantMinted> {
        let holder = caller.holder();
        let (target, effector) = self.route_grant(&holder, target, &*delivery)?;
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        let (_, custody) = handle_record_in_txn(&self.store, &wtxn, handle)?;
        let rec = live_record_in_txn(&self.store, &wtxn, &custody)?;
        let stamped = self.stamp_grant_in_txn(
            &mut wtxn,
            now,
            GrantAsk {
                holder,
                custody,
                rec: &rec,
                effector: &effector,
                target,
                ttl_secs: grant_ttl(ttl_secs),
                not_after,
                registered: None,
            },
        )?;
        wtxn.commit()?;
        self.deliver_stamped(stamped, delivery, None)
    }

    /// Renews the grant `grant` that `caller` holds: a FRESH grant at the
    /// record's CURRENT generation, under the record's binding and the live
    /// floor as they stand now, to the same target, with a new lease for a
    /// T1/T2 grant. It never extends `expires_at` over bytes already handed
    /// out. The renewed grant is retired as `replaced`: a door or local grant
    /// in the same writer, a T1 grant per [`super::SECRET_GRANT_RENEW_HANDOVER`].
    /// A T2 renewal writes the new value into the file the old registration
    /// holds and takes that registration over (one path per lease, the file
    /// identity kept). A stale grant renews; an expired or retired one does
    /// not (mint a fresh one).
    ///
    /// # Errors
    /// As [`Self::mint_secret_grant`], and
    /// [`SecretError::SecretLeaseNotFound`] for a grant `caller` does not
    /// hold, [`SecretError::SecretLeaseNotActive`] for one that expired or
    /// was retired, [`SecretError::SecretGrantTargetMismatch`] when its
    /// target now presents for another effector.
    pub fn renew_secret_grant(
        &self,
        caller: &SecretGrantCaller,
        grant: &EntityId,
        ttl_secs: Option<u64>,
        not_after: Option<u64>,
        delivery: &mut dyn SecretHostDelivery,
    ) -> Result<SecretGrantMinted> {
        let holder = caller.holder();
        let held = {
            let txn = self.store.env.read_txn()?;
            read_held_grant_in_txn(&self.store, &txn, grant, &holder)?
        };
        let (target, effector) = self.route_grant(&holder, held.target.clone(), &*delivery)?;
        if effector != held.effector {
            return Err(grant_mismatch(
                *grant,
                "its target now presents for another effector; mint a fresh grant",
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        let mut old =
            match live_held_grant_in_txn(&self.store, &mut wtxn, grant, &holder, now.secs()) {
                Ok(old) => old,
                Err(error) => {
                    wtxn.commit()?;
                    return Err(error);
                }
            };
        let rec = live_record_in_txn(&self.store, &wtxn, &old.custody)?;
        // A T2 renewal takes over the file the old registration holds.
        let moved = match (&old.target, old.lease) {
            (SecretGrantTarget::LocalFile { path, .. }, Some(lease)) => {
                read_local_registration_in_txn(&self.store, &wtxn, &lease)?
                    .filter(|stored| stored.registration.path == Path::new(path))
                    .map(|stored| (lease, stored.file_identity))
            }
            _ => None,
        };
        let stamped = self.stamp_grant_in_txn(
            &mut wtxn,
            now,
            GrantAsk {
                holder: old.holder,
                custody: old.custody,
                rec: &rec,
                effector: &effector,
                target,
                ttl_secs: grant_ttl(ttl_secs),
                not_after,
                registered: moved.map(|(_, identity)| identity),
            },
        )?;
        let retire_now = stamped.value.is_none()
            || SECRET_GRANT_RENEW_HANDOVER == SecretGrantHandover::BeforeDelivery;
        if retire_now {
            if let Some((lease, _)) = moved {
                // The file is the new lease's now: the old row goes first, so
                // retiring the old lease tears no file down.
                SECRET_LOCAL_REGISTRATION.delete(&self.store, &mut wtxn, &HexId(lease))?;
            }
            retire_grant_in_txn(
                &self.store,
                &mut wtxn,
                &mut old,
                SecretGrantStatus::Replaced,
                Some(stamped.grant.grant_id),
                now.secs(),
            )?;
        }
        wtxn.commit()?;
        self.deliver_stamped(stamped, delivery, (!retire_now).then_some(old.grant_id))
    }

    /// The target as a grant keeps it, and the effector it presents for:
    /// the operation table's, the connector route's, the run host's for its
    /// destination, or the one a T2 target names.
    fn route_grant(
        &self,
        holder: &SecretGrantHolder,
        target: SecretGrantTarget,
        delivery: &dyn SecretHostDelivery,
    ) -> Result<(SecretGrantTarget, String)> {
        match target {
            SecretGrantTarget::Operation { name } => {
                let op = SECRET_USE_OPERATIONS
                    .iter()
                    .find(|op| op.name == name)
                    .ok_or(Error::Gate(GateError::InvalidConsentBound(
                        "a door grant names one of self.use's operations, such as slack.auth_test",
                    )))?;
                Ok((
                    SecretGrantTarget::Operation { name },
                    op.effector.to_owned(),
                ))
            }
            SecretGrantTarget::Connector { name } => {
                let route = self.route_connector_call(&name)?.ok_or(Error::Gate(
                    GateError::InvalidConsentBound(
                        "a connector grant names a catalogued connector a call can route to",
                    ),
                ))?;
                let effector = connector_call_effector(&route);
                Ok((SecretGrantTarget::Connector { name: route.name }, effector))
            }
            SecretGrantTarget::HostDestination { name } => {
                let effector = delivery
                    .destination_effector(holder, &name)
                    .ok_or_else(|| no_destination(&name))?;
                Ok((SecretGrantTarget::HostDestination { name }, effector))
            }
            SecretGrantTarget::LocalFile {
                effector,
                path,
                project_id,
            } => {
                let named = effector.clone();
                Ok((
                    SecretGrantTarget::LocalFile {
                        effector,
                        path,
                        project_id,
                    },
                    named,
                ))
            }
        }
    }

    /// Stamps one grant in `wtxn` at `now`: the binding's read grant, then
    /// the rung's admission and rows. Writes nothing the caller may commit
    /// when it refuses.
    fn stamp_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        now: VaultInstant,
        ask: GrantAsk<'_>,
    ) -> Result<Stamped> {
        let GrantAsk {
            holder,
            custody,
            rec,
            effector,
            target,
            ttl_secs,
            not_after,
            registered,
        } = ask;
        if !rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            return Err(Error::Secret(SecretError::SecretBindingDenied {
                effector: effector.to_owned(),
                secret_ref: rec.name.clone(),
            }));
        }
        let mut grant = SecretLeaseGrant {
            grant_id: self.store.clock.entity_id()?,
            custody,
            generation: rec.rotation_generation,
            holder,
            effector: effector.to_owned(),
            tier: target.tier(),
            target,
            granted_at: now.secs(),
            expires_at: grant_expiry(now.secs(), ttl_secs, not_after)?,
            status: SecretGrantStatus::Active,
            lease: None,
            replaced_by: None,
            sends: 0,
        };
        let (mut lease, mut registration, mut value, mut guard) = (None, None, None, None);
        if grant.tier == CustodyTier::T0Doored {
            // A redemption right only: no lease, no value read.
            let floor = SecretCustodyFloor::resolve(&self.store, wtxn)?;
            admit_record_use(rec, effector, CustodyTier::T0Doored, &floor)?;
            crate::credential_door::admit_materialization_in_txn(
                &self.store,
                wtxn,
                effector,
                None,
            )?;
        } else {
            let minted = stamp_secret_lease_in_txn(
                self,
                wtxn,
                &rec.name,
                effector,
                ttl_secs,
                now,
                not_after.map(VaultInstant),
            )?;
            let mut leased = minted.lease;
            grant.generation = leased.value_generation;
            grant.granted_at = leased.granted_at;
            grant.expires_at = leased.expires_at;
            grant.lease = Some(leased.lease_id);
            if let SecretGrantTarget::LocalFile {
                path, project_id, ..
            } = &grant.target
            {
                let path = Path::new(path);
                let id = self.admit_local_in_txn(wtxn, &leased, path)?;
                let (local, file) =
                    self.write_local_in_txn(wtxn, &mut leased, &id, path, project_id, registered)?;
                registration = Some(local);
                guard = Some(file);
            } else {
                value = Some(minted.value);
            }
            lease = Some(leased);
        }
        write_grant_in_txn(&self.store, wtxn, &grant)?;
        Ok(Stamped {
            grant,
            lease,
            registration,
            value,
            guard,
        })
    }

    /// After the writer committed: the T2 file is the row's, the T1 bytes go
    /// to their destination, and the grant `replaces` (a T1 renewal's
    /// predecessor) retires once they landed. A delivery that fails revokes
    /// the new grant and its lease and answers why.
    fn deliver_stamped(
        &self,
        stamped: Stamped,
        delivery: &mut dyn SecretHostDelivery,
        replaces: Option<EntityId>,
    ) -> Result<SecretGrantMinted> {
        let Stamped {
            grant,
            lease,
            registration,
            value,
            guard,
        } = stamped;
        if let Some(guard) = guard {
            guard.disarm();
        }
        if let (Some(value), SecretGrantTarget::HostDestination { name }) = (value, &grant.target)
            && let Err(error) = delivery.deliver(&grant.holder, name, &value)
        {
            self.retire_secret_grant(&grant.grant_id, SecretGrantStatus::Revoked, None)?;
            return Err(error);
        }
        if let Some(old) = replaces {
            self.retire_secret_grant(&old, SecretGrantStatus::Replaced, Some(grant.grant_id))?;
        }
        Ok(SecretGrantMinted {
            grant,
            lease,
            registration,
        })
    }

    /// Retires one grant the engine itself just minted or replaced, in a
    /// writer of its own.
    fn retire_secret_grant(
        &self,
        grant: &EntityId,
        status: SecretGrantStatus,
        replaced_by: Option<EntityId>,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let at = self.instant_in_write_txn(&mut wtxn)?.secs();
        if let Some(mut row) = read_grant_in_txn(&self.store, &wtxn, grant)? {
            retire_grant_in_txn(&self.store, &mut wtxn, &mut row, status, replaced_by, at)?;
        }
        wtxn.commit()?;
        Ok(())
    }
}

/// The admission projection of the custody record `custody` while it is the
/// live record its name resolves to and active: a grant never follows a name
/// to a record registered since.
pub(super) fn live_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    custody: &EntityId,
) -> Result<SecretCustodyAdmission> {
    let rec = read_secret_custody_admission_in_txn(store, txn, custody)?.ok_or_else(|| {
        Error::Secret(SecretError::SecretRefNotFound {
            name: custody.to_hex(),
        })
    })?;
    let live = resolve_secret_ref_in_txn(store, txn, &rec.name)? == Some(*custody);
    if !live || rec.status != SecretCustodyStatus::Active {
        return Err(Error::Secret(SecretError::SecretCustodyNotActive {
            name: rec.name,
        }));
    }
    Ok(rec)
}

/// The lifetime a grant asks for, at least a second and at most the cap.
fn grant_ttl(ttl_secs: Option<u64>) -> u64 {
    ttl_secs
        .unwrap_or(SECRET_GRANT_DEFAULT_TTL_SECS)
        .clamp(1, SECRET_GRANT_MAX_TTL_SECS)
}

/// A door grant's expiry: `now + ttl`, never past `not_after`; a bound
/// already elapsed refuses before anything is written.
fn grant_expiry(now: u64, ttl_secs: u64, not_after: Option<u64>) -> Result<u64> {
    match not_after {
        Some(bound) if now >= bound => Err(Error::InvariantViolation(
            "secret grant expiry bound elapsed before the grant was stamped",
        )),
        Some(bound) => Ok(now.saturating_add(ttl_secs).min(bound)),
        None => Ok(now.saturating_add(ttl_secs)),
    }
}
