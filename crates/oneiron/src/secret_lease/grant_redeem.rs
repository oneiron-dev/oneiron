//! FIX 4313: redeeming, checking, reading and tearing down a secret grant.
//!
//! A redemption rechecks everything on ONE witnessed vault instant
//! ([`Vault::instant_in_write_txn`], the clock #1539 moved checkout claims
//! onto; never a caller's `now`): the holder, the grant's status and expiry,
//! its target, the live custody record, its binding and the live floor, and
//! the generation the grant pins. A grant minted before the record rotated
//! refuses after it. A teardown checks only who holds the grant, so a stale,
//! expired or replaced grant can always be cleaned up.

use super::admission::admit_record_use;
use super::delivery::SecretHostDelivery;
use super::grant::{
    SECRET_GRANT_T0_MAX_SENDS, SECRET_GRANT_TEARDOWN_KEPT_REFUSES, SecretCleanup,
    SecretGrantCaller, SecretGrantRedemption, SecretGrantRef, SecretGrantStatus, SecretGrantTarget,
    SecretGrantTeardown, SecretLeaseGrant, grant_mismatch, live_held_grant_in_txn,
    read_held_grant_in_txn, retire_grant_in_txn, write_grant_in_txn,
};
use super::grant_doors::live_record_in_txn;
use super::storage::{read_secret_lease_in_txn, read_value_for_ref_in_txn};
use super::types::{SecretLeaseStatus, VaultInstant};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{CustodyTier, SecretBinding, SecretCustodyFloor};
use crate::vault::Vault;

/// Why a leased or local grant does not redeem at a door: its value went to
/// its destination, never to a door's send.
const DOOR_ONLY: &str = "only a door grant redeems at a door";

/// What a connector grant's redemption at a door came to: the redemption,
/// or the issuer hold that counted nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorGrantRedemption {
    /// The grant redeemed; the redemption counted one send.
    Redeemed(SecretGrantRedemption),
    /// The call's row meets an issuer change the owner has not accepted:
    /// no send was counted and `apply` never ran.
    Held { reason: &'static str },
}

impl Vault {
    /// Redeems the door grant `grant` for `target` and runs `apply` INSIDE
    /// the door with the value, as [`Vault::inject_secret_record_at_door`]
    /// does: `apply` returns only `()`, and the answer holds no value. Every
    /// check of a redemption runs under one witnessed instant, and the value
    /// is read in the same writer, at the generation the grant pins; the
    /// writer is released before `apply` runs. A redemption counts one send.
    ///
    /// A connector call made under a grant redeems here at every real send,
    /// a held send resumed later included.
    ///
    /// # Errors
    /// [`SecretError::SecretLeaseNotFound`] for a grant the presenter does
    /// not hold; [`SecretError::SecretLeaseNotActive`] for one expired,
    /// revoked or replaced; [`SecretError::SecretGrantTargetMismatch`] for
    /// another target or a leased grant; [`SecretError::SecretGrantSpent`];
    /// [`SecretError::SecretGrantStale`] once the record rotated past the
    /// pinned generation; the record, binding, floor and door policy
    /// refusals.
    pub fn redeem_secret_grant_at_door(
        &self,
        grant: &SecretGrantRef,
        target: &SecretGrantTarget,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<SecretGrantRedemption> {
        if target.tier() != CustodyTier::T0Doored {
            return Err(grant_mismatch(grant.grant(), DOOR_ONLY));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        let row = match self.admit_grant_in_txn(&mut wtxn, grant, target, now, true) {
            Ok(row) => row,
            Err(error) => {
                // A lazy expiry lands even though the redemption refuses.
                wtxn.commit()?;
                return Err(error);
            }
        };
        let value = read_value_for_ref_in_txn(self, &wtxn, &row.custody, &row.effector)?;
        wtxn.commit()?;
        apply(&value)?;
        Ok(SecretGrantRedemption {
            grant_id: row.grant_id,
            generation: row.generation,
            effector: row.effector,
            redeemed_at: now.secs(),
        })
    }

    /// Redeems the door grant `grant` for `target` on the connector call's
    /// row (`key_ref`, `tool`), as [`Self::redeem_secret_grant_at_door`]
    /// does, and runs `apply` INSIDE the door with the value. The row's
    /// issuer binding is read in the same writer before the send is
    /// counted: while an issuer change the owner has not accepted holds the
    /// row, no send is counted, `apply` never runs, and the answer is
    /// [`ConnectorGrantRedemption::Held`].
    ///
    /// # Errors
    /// As [`Self::redeem_secret_grant_at_door`].
    pub fn redeem_connector_grant_at_door(
        &self,
        grant: &SecretGrantRef,
        target: &SecretGrantTarget,
        key_ref: &EntityId,
        tool: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<ConnectorGrantRedemption> {
        if target.tier() != CustodyTier::T0Doored {
            return Err(grant_mismatch(grant.grant(), DOOR_ONLY));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        if let Some(reason) = crate::connector_key::connector_issuer_hold_reason_in_txn(
            &self.store,
            &wtxn,
            key_ref,
            tool,
        )? {
            drop(wtxn);
            return Ok(ConnectorGrantRedemption::Held { reason });
        }
        let row = match self.admit_grant_in_txn(&mut wtxn, grant, target, now, true) {
            Ok(row) => row,
            Err(error) => {
                // A lazy expiry lands even though the redemption refuses.
                wtxn.commit()?;
                return Err(error);
            }
        };
        let value = read_value_for_ref_in_txn(self, &wtxn, &row.custody, &row.effector)?;
        wtxn.commit()?;
        apply(&value)?;
        Ok(ConnectorGrantRedemption::Redeemed(SecretGrantRedemption {
            grant_id: row.grant_id,
            generation: row.generation,
            effector: row.effector,
            redeemed_at: now.secs(),
        }))
    }

    /// Whether `grant` would redeem for `target` now, with no value read and
    /// no send counted: every check [`Self::redeem_secret_grant_at_door`]
    /// makes, and for a leased or local grant, that its lease is still live.
    /// Answers the grant row.
    ///
    /// # Errors
    /// As [`Self::redeem_secret_grant_at_door`], past the door-only rule.
    pub fn check_secret_grant(
        &self,
        grant: &SecretGrantRef,
        target: &SecretGrantTarget,
    ) -> Result<SecretLeaseGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        let admitted = self.admit_grant_in_txn(&mut wtxn, grant, target, now, false);
        wtxn.commit()?;
        admitted
    }

    /// The grant `caller` holds, as it stands now (a past-due active grant
    /// reads as expired). Value-free.
    ///
    /// # Errors
    /// [`SecretError::SecretLeaseNotFound`] for a grant `caller` does not
    /// hold.
    pub fn secret_grant(
        &self,
        caller: &SecretGrantCaller,
        grant: &EntityId,
    ) -> Result<SecretLeaseGrant> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?;
        let mut row = read_held_grant_in_txn(&self.store, &txn, grant, &caller.holder())?;
        if row.status == SecretGrantStatus::Active && now.secs() >= row.expires_at {
            row.status = SecretGrantStatus::Expired;
        }
        Ok(row)
    }

    /// Tears down the grant `grant` that `caller` holds, whatever its state:
    /// a stale, expired, revoked or replaced grant tears down too, so no
    /// refusal ever blocks cleanup. An active or expired grant is revoked;
    /// the lease it rides is revoked and its T2 file removed; a T1
    /// destination is cleared through `delivery`. A replaced grant's
    /// destination holds its successor's bytes and is left alone. Answers
    /// what the cleanup found (see [`super::SECRET_GRANT_TEARDOWN_KEPT_REFUSES`]).
    /// Bytes a process already copied are beyond the vault's reach.
    ///
    /// # Errors
    /// [`SecretError::SecretLeaseNotFound`] for a grant `caller` does not
    /// hold; [`SecretError::SecretGrantCleanupKept`] when the cleanup kept a
    /// copy and the teardown rule says so.
    pub fn teardown_secret_grant(
        &self,
        caller: &SecretGrantCaller,
        grant: &EntityId,
        delivery: &mut dyn SecretHostDelivery,
    ) -> Result<SecretGrantTeardown> {
        let mut wtxn = self.store.env.write_txn()?;
        let now = self.instant_in_write_txn(&mut wtxn)?;
        let mut row = read_held_grant_in_txn(&self.store, &wtxn, grant, &caller.holder())?;
        let replaced = row.status == SecretGrantStatus::Replaced;
        let file = retire_grant_in_txn(
            &self.store,
            &mut wtxn,
            &mut row,
            SecretGrantStatus::Revoked,
            None,
            now.secs(),
        )?;
        wtxn.commit()?;
        let cleanup = match &row.target {
            SecretGrantTarget::HostDestination { .. } if replaced => SecretCleanup::Absent,
            // FIX 7954: a stale teardown clears only its own grant's copy.
            SecretGrantTarget::HostDestination { name } => delivery
                .withdraw(&row.holder, &row.grant_id, name)
                .unwrap_or(SecretCleanup::Kept),
            _ => file,
        };
        if SECRET_GRANT_TEARDOWN_KEPT_REFUSES && cleanup == SecretCleanup::Kept {
            return Err(Error::Secret(SecretError::SecretGrantCleanupKept {
                grant_id: row.grant_id,
            }));
        }
        Ok(SecretGrantTeardown {
            grant: row,
            cleanup,
        })
    }

    /// Every check of one redemption, in `wtxn` at `now`. A lazy expiry is
    /// written into `wtxn` before it refuses; a counted send is written once
    /// every check passed.
    fn admit_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grant: &SecretGrantRef,
        target: &SecretGrantTarget,
        now: VaultInstant,
        count: bool,
    ) -> Result<SecretLeaseGrant> {
        let mut row = live_held_grant_in_txn(
            &self.store,
            wtxn,
            &grant.grant(),
            &grant.holder(),
            now.secs(),
        )?;
        if row.target != *target {
            return Err(grant_mismatch(
                row.grant_id,
                "it names another operation, connector or destination",
            ));
        }
        let door = row.tier == CustodyTier::T0Doored;
        if door && SECRET_GRANT_T0_MAX_SENDS.is_some_and(|max| row.sends >= max) {
            return Err(Error::Secret(SecretError::SecretGrantSpent {
                grant_id: row.grant_id,
                sends: row.sends,
            }));
        }
        let rec = live_record_in_txn(&self.store, wtxn, &row.custody)?;
        if rec.rotation_generation != row.generation {
            return Err(Error::Secret(SecretError::SecretGrantStale {
                grant_id: row.grant_id,
                pinned_generation: row.generation,
                current_generation: rec.rotation_generation,
            }));
        }
        if !rec
            .binding_for(&row.effector)
            .is_some_and(SecretBinding::grants_read)
        {
            return Err(Error::Secret(SecretError::SecretBindingDenied {
                effector: row.effector,
                secret_ref: rec.name,
            }));
        }
        let floor = SecretCustodyFloor::resolve(&self.store, wtxn)?;
        admit_record_use(&rec, &row.effector, row.tier, &floor)?;
        crate::credential_door::admit_materialization_in_txn(
            &self.store,
            wtxn,
            &row.effector,
            None,
        )?;
        if let Some(lease_id) = row.lease {
            match read_secret_lease_in_txn(&self.store, wtxn, &lease_id)? {
                Some(lease)
                    if lease.status == SecretLeaseStatus::Active
                        && now.secs() < lease.expires_at => {}
                Some(lease) => {
                    return Err(Error::Secret(SecretError::SecretLeaseNotActive {
                        lease_id,
                        status: match lease.status {
                            SecretLeaseStatus::Active => SecretLeaseStatus::Expired,
                            status => status,
                        },
                    }));
                }
                None => {
                    return Err(Error::Secret(SecretError::SecretLeaseNotFound { lease_id }));
                }
            }
        }
        if count && door {
            row.sends = row.sends.saturating_add(1);
            write_grant_in_txn(&self.store, wtxn, &row)?;
        }
        Ok(row)
    }
}
