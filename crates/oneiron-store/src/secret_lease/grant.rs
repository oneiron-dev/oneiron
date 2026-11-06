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

use crate::attempt_id::AttemptId;
use crate::secret_record::types::CustodyTier;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron_contracts::secret_lease::SecretLeaseStatus;

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

/// Who holds a grant: its principal, and the run it is bound to, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantHolder {
    pub principal: EntityId,
    pub run: Option<AttemptId>,
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
    pub fn admits(&self, presenter: &Self) -> bool {
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
    pub grant: EntityId,
    pub holder: SecretGrantHolder,
}

impl SecretGrantRef {
    pub const fn new(grant: EntityId, holder: SecretGrantHolder) -> Self {
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
    pub const fn as_lease_status(self) -> SecretLeaseStatus {
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

/// The refusal of a grant presented for a use it does not bind.
pub fn grant_mismatch(grant: EntityId, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretGrantTargetMismatch {
        grant_id: grant,
        reason,
    })
}
