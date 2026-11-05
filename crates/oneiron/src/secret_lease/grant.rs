//! Core half of `secret_lease::grant`: its store-layer items live in `oneiron_store::secret_lease::grant` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::secret_lease::grant::*;

use super::storage::{read_local_registration_in_txn, teardown_local_registration_in_txn};
use super::types::{LocalRegistration, SecretLease, SecretLeaseStatus};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::memory::{Memory, verify_actor_binding};
use crate::secret_record::CustodyTier;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::attempt_id::AttemptId;
use crate::vault::Vault;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// The grant rows. Key: id16 (grant id).
pub(super) const SECRET_LEASE_GRANTS: SideTable<EntityId, SecretLeaseGrant, Named> =
    SideTable::new(&side_table::SECRET_LEASE_GRANT);

/// The caller a grant is minted for, renewed by, torn down by or used by: a
/// verified actor of a session that keeps a record, and the run it acts in
/// when its host attached one. Only [`SecretGrantCaller::of`] makes one, from
/// the caller's own bound scope; no proof is synthesized for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretGrantCaller {
    actor: EntityId,
    actor_class: EdgeActorClass,
    run: Option<AttemptId>,
}

impl SecretGrantCaller {
    /// The caller `memory` is bound to, acting in `run` when the host
    /// attached that run to this credential. The run only narrows: a grant
    /// minted for a run is redeemed only within it.
    ///
    /// # Errors
    /// The actor binding's refusal, and FORBIDDEN for an anonymous off-record
    /// session: a grant keeps a durable row and its uses keep receipts.
    pub fn of(memory: &Memory<'_>, run: Option<AttemptId>) -> MemoryResult<Self> {
        verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
        if memory.keeps_no_record() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a secret grant keeps a durable row and its uses keep receipts; an anonymous \
                 off-record session keeps none",
                &["Ask for the grant outside the anonymous session."],
            ));
        }
        Ok(Self {
            actor: memory.actor(),
            actor_class: memory.actor_class(),
            run,
        })
    }

    /// Who a grant minted for this caller is held by.
    #[must_use]
    pub const fn holder(&self) -> SecretGrantHolder {
        SecretGrantHolder {
            principal: self.actor,
            run: self.run,
        }
    }

    pub(crate) const fn actor(&self) -> EntityId {
        self.actor
    }

    pub(crate) const fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }
}

/// What a mint or a renewal made. No value, no buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretGrantMinted {
    pub grant: SecretLeaseGrant,
    /// The lease a T1/T2 grant rides.
    pub lease: Option<SecretLease>,
    /// A T2 grant's file registration.
    pub registration: Option<LocalRegistration>,
}

pub(super) fn read_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<Option<SecretLeaseGrant>> {
    SECRET_LEASE_GRANTS.get(store, txn, grant)
}

pub(super) fn write_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: &SecretLeaseGrant,
) -> Result<()> {
    SECRET_LEASE_GRANTS.put(store, wtxn, &grant.grant_id, grant)
}

/// The grant `presenter` may act on. An unknown grant and another holder's
/// both answer as not found, so a grant id tells a stranger nothing.
pub(super) fn read_held_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
    presenter: &SecretGrantHolder,
) -> Result<SecretLeaseGrant> {
    match read_grant_in_txn(store, txn, grant)? {
        Some(row) if row.holder.admits(presenter) => Ok(row),
        _ => Err(Error::Secret(SecretError::SecretLeaseNotFound {
            lease_id: *grant,
        })),
    }
}

/// [`read_held_grant_in_txn`] for a use: a past-due active grant is expired
/// in place (the caller commits that even when it refuses), and any status
/// but active refuses.
pub(super) fn live_held_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: &EntityId,
    presenter: &SecretGrantHolder,
    now: u64,
) -> Result<SecretLeaseGrant> {
    let mut row = read_held_grant_in_txn(store, wtxn, grant, presenter)?;
    if row.status == SecretGrantStatus::Active && now >= row.expires_at {
        row.status = SecretGrantStatus::Expired;
        write_grant_in_txn(store, wtxn, &row)?;
    }
    if row.status != SecretGrantStatus::Active {
        return Err(Error::Secret(SecretError::SecretLeaseNotActive {
            lease_id: row.grant_id,
            status: row.status.as_lease_status(),
        }));
    }
    Ok(row)
}

/// Retires `grant` in `wtxn`: an active or expired grant takes `status` (and
/// `replaced_by`), its lease is revoked and a T2 file it registered is torn
/// down. A grant already revoked or replaced keeps its status, and its lease
/// is retired again, so a teardown retries a file an earlier one kept.
/// Answers what the T2 cleanup found (`Absent` for a grant with no file).
pub(super) fn retire_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: &mut SecretLeaseGrant,
    status: SecretGrantStatus,
    replaced_by: Option<EntityId>,
    at: u64,
) -> Result<SecretCleanup> {
    if matches!(
        grant.status,
        SecretGrantStatus::Active | SecretGrantStatus::Expired
    ) {
        grant.status = status;
        grant.replaced_by = replaced_by;
        write_grant_in_txn(store, wtxn, grant)?;
    }
    match grant.lease {
        Some(lease) => retire_lease_in_txn(store, wtxn, &lease, at),
        None => Ok(SecretCleanup::Absent),
    }
}

/// Revokes the lease `lease_id` in `wtxn` and tears down its T2 file through
/// the one teardown body. Answers what the file cleanup found.
pub(super) fn retire_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    at: u64,
) -> Result<SecretCleanup> {
    if let Some(mut lease) = super::storage::read_secret_lease_in_txn(store, wtxn, lease_id)?
        && lease.status != SecretLeaseStatus::Revoked
    {
        lease.status = SecretLeaseStatus::Revoked;
        super::storage::write_secret_lease_in_txn(store, wtxn, &lease)?;
    }
    if read_local_registration_in_txn(store, wtxn, lease_id)?.is_none() {
        return Ok(SecretCleanup::Absent);
    }
    teardown_local_registration_in_txn(store, wtxn, lease_id, at)?;
    Ok(
        match read_local_registration_in_txn(store, wtxn, lease_id)? {
            Some(_) => SecretCleanup::Kept,
            None => SecretCleanup::Removed,
        },
    )
}

/// An actor's erase (FIX 3520): every grant the actor holds goes, and the
/// lease each rides is revoked with its T2 file torn down. A T1 copy already
/// in a process is beyond the vault's reach, as at any teardown.
pub(crate) fn erase_secret_grant_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut at = None;
    for (grant, row) in SECRET_LEASE_GRANTS.scan(&vault.store, wtxn)? {
        if row.holder.principal != *actor {
            continue;
        }
        if let Some(lease) = row.lease {
            let now = match at {
                Some(now) => now,
                None => *at.insert(crate::ports::recorded_at_in_txn(&vault.store, wtxn)?),
            };
            retire_lease_in_txn(&vault.store, wtxn, &lease, now)?;
        }
        SECRET_LEASE_GRANTS.delete(&vault.store, wtxn, &grant)?;
    }
    Ok(())
}
