//! FIX 4313: the value-free grant a secret lease's holder redeems.
//!
//! A [`SecretLease`] row says a value was materialized; it cannot say who
//! holds the right to it, for what, or at which value generation. A
//! [`SecretLeaseGrant`] sits beside it and says exactly that: the custody
//! record, the value generation it pins, the holder (a verified principal and,
//! when the host attached one, the run it acts in), the effector, the target
//! and the expiry. A door (T0) grant is only a redemption right: no lease, no
//! workspace buffer. A leased (T1) or local (T2) grant rides the lease minted
//! with it in the same committing writer.
//!
//! The grant is the only limit. It binds a holder, an effector, a target and an
//! expiry, never a location, a substrate or a hosted or self-hosted mode.
//!
//! Rotation is lease-scoped (ARCH-0069 S6) and stays as it is: it revokes
//! nothing and walks no lease. A grant pins the generation it was minted at,
//! so a redemption after the record rotates refuses with
//! [`SecretError::SecretGrantStale`] and the holder renews. Bytes already
//! delivered before the rotation (a T1 process environment, a T2 file, a
//! connector send) are not recalled: the vault cannot reach process memory.

use serde::{Deserialize, Serialize};

use super::storage::{read_local_registration_in_txn, teardown_local_registration_in_txn};
use super::types::{LocalRegistration, SecretLease, SecretLeaseStatus};
use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding,
};
use crate::secret_custody::CustodyTier;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::Vault;

/// The lifetime a grant takes when its caller names none, in seconds. One
/// constant, so a ruling changes one line (CALLS: FIX 4313 grant TTL).
pub const SECRET_GRANT_DEFAULT_TTL_SECS: u64 = 900;

/// The longest lifetime one grant takes, in seconds. A longer ask is cut to
/// it, and the answer's `expires_at` says so; a holder that needs longer
/// renews. A T1/T2 grant for a door effector also meets the credential
/// door's own lease ceiling, which refuses a longer lease (CALLS: FIX 4313
/// grant TTL).
pub const SECRET_GRANT_MAX_TTL_SECS: u64 = 3600;

/// How many sends a door (T0) grant makes. `None`: any number of sends to
/// its one target until it expires (CALLS: FIX 4313 T0 use count).
pub const SECRET_GRANT_T0_MAX_SENDS: Option<u32> = None;

/// When a T1 renewal retires the grant it replaces (CALLS: FIX 4313 renew
/// handover).
pub const SECRET_GRANT_RENEW_HANDOVER: SecretGrantHandover = SecretGrantHandover::AfterDelivery;

/// Whether a teardown whose cleanup kept a copy answers with a refusal, once
/// the revoke has committed, instead of an answer that says `kept`
/// (CALLS: FIX 4313 teardown reporting).
pub const SECRET_GRANT_TEARDOWN_KEPT_REFUSES: bool = false;

/// The grant rows. Key: id16 (grant id).
pub(super) const SECRET_LEASE_GRANTS: SideTable<EntityId, SecretLeaseGrant, Named> =
    SideTable::new(&side_table::SECRET_LEASE_GRANT);

/// When a T1 renewal retires the grant it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretGrantHandover {
    /// The old grant stays live until the new grant's bytes reach the
    /// destination; a failed delivery leaves the old grant as it was.
    AfterDelivery,
    /// The old grant retires in the writer that mints the new one; a failed
    /// delivery then leaves neither live.
    BeforeDelivery,
}

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

/// Who holds a grant: its principal, and the run it is bound to, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantHolder {
    principal: EntityId,
    run: Option<AttemptId>,
}

impl SecretGrantHolder {
    /// The holder's verified principal.
    #[must_use]
    pub const fn principal(&self) -> EntityId {
        self.principal
    }

    /// The run the grant is bound to, if it is bound to one.
    #[must_use]
    pub const fn run(&self) -> Option<AttemptId> {
        self.run
    }

    /// Whether `presenter` may act on a grant this holder holds: the same
    /// principal and, for a grant bound to a run, the same run.
    pub(super) fn admits(&self, presenter: &Self) -> bool {
        self.principal == presenter.principal
            && self.run.is_none_or(|run| presenter.run == Some(run))
    }
}

/// A grant as a send carries it to its door: the grant and the holder that
/// presents it. The engine makes one from a verified caller; a held
/// connector call keeps it on its row, so every send redeems it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantRef {
    grant: EntityId,
    holder: SecretGrantHolder,
}

impl SecretGrantRef {
    pub(crate) const fn new(grant: EntityId, holder: SecretGrantHolder) -> Self {
        Self { grant, holder }
    }

    /// The grant's id.
    #[must_use]
    pub const fn grant(&self) -> EntityId {
        self.grant
    }

    /// The holder that presents it.
    #[must_use]
    pub const fn holder(&self) -> SecretGrantHolder {
        self.holder
    }
}

/// Where a grant's value may go. The rung follows from it: a door target is
/// T0, a host destination T1, a local file T2. Never a location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretGrantTarget {
    /// T0: one operation of `self.use`'s table, by its name.
    Operation { name: String },
    /// T0: connector calls on one catalogued connector, by the catalog name
    /// its route answers (`ConnectorCallRoute::name`).
    Connector { name: String },
    /// T1: a destination the caller's run host registered for it (a process
    /// environment variable, a CLI credential slot), by the host's name for
    /// it. The host names its effector ([`super::SecretHostDelivery`]).
    HostDestination { name: String },
    /// T2: a manifest-declared local path of the record, for one project,
    /// under the effector the host names for it.
    LocalFile {
        effector: String,
        path: String,
        project_id: String,
    },
}

impl SecretGrantTarget {
    /// The rung a grant for this target takes.
    #[must_use]
    pub const fn tier(&self) -> CustodyTier {
        match self {
            Self::Operation { .. } | Self::Connector { .. } => CustodyTier::T0Doored,
            Self::HostDestination { .. } => CustodyTier::T1Leased,
            Self::LocalFile { .. } => CustodyTier::T2LocalRegistered,
        }
    }
}

/// A grant's lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretGrantStatus {
    /// Redeemable within its bindings until it expires.
    Active,
    /// Past `expires_at`.
    Expired,
    /// Torn down, or retired by a failed delivery. Terminal.
    Revoked,
    /// Retired by its renewal; `replaced_by` names the successor. Terminal.
    Replaced,
}

impl SecretGrantStatus {
    /// The lease status a refusal names: a replaced grant reads as revoked.
    const fn as_lease_status(self) -> SecretLeaseStatus {
        match self {
            Self::Active => SecretLeaseStatus::Active,
            Self::Expired => SecretLeaseStatus::Expired,
            Self::Revoked | Self::Replaced => SecretLeaseStatus::Revoked,
        }
    }
}

/// One grant row. It holds no value, no digest of one and no copy of one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaseGrant {
    pub grant_id: EntityId,
    /// The custody record the grant redeems.
    pub custody: EntityId,
    /// The record's rotation generation the grant pins.
    pub generation: u32,
    pub holder: SecretGrantHolder,
    /// The effector the record's binding must name.
    pub effector: String,
    pub target: SecretGrantTarget,
    /// The rung, from the target.
    pub tier: CustodyTier,
    pub granted_at: u64,
    pub expires_at: u64,
    pub status: SecretGrantStatus,
    /// The T1/T2 lease the grant rides; `None` for a door grant.
    pub lease: Option<EntityId>,
    /// The grant a renewal minted in this one's place.
    pub replaced_by: Option<EntityId>,
    /// How many times the grant was redeemed at a door.
    pub sends: u32,
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

/// One redemption at a door. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretGrantRedemption {
    pub grant_id: EntityId,
    /// The generation the value was read at: the one the grant pins.
    pub generation: u32,
    pub effector: String,
    pub redeemed_at: u64,
}

/// What a teardown's cleanup found of the copy the grant delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretCleanup {
    /// The file or destination held the copy, and it is gone.
    Removed,
    /// Nothing was there to clean: a door grant, a copy already gone, or a
    /// destination its replacement now holds.
    Absent,
    /// The copy could not be removed. A T2 row stays and keeps its path
    /// excluded until the retry sweep removes it.
    Kept,
}

/// What a teardown came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretGrantTeardown {
    pub grant: SecretLeaseGrant,
    pub cleanup: SecretCleanup,
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

/// The refusal of a grant presented for a use it does not bind.
pub(super) fn grant_mismatch(grant: EntityId, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretGrantTargetMismatch {
        grant_id: grant,
        reason,
    })
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
