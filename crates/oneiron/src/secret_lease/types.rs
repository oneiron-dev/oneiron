//! Lease/registration/receipt row types, VaultInstant clock, key prefixes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::authority::{
    authority_first_seen_clock_sync_key, authority_observation_secs,
    decode_authority_first_seen_secs,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::CustodyTier;
use crate::unix_seconds_now;
use crate::vault::Vault;

/// The `vault_meta` key prefix for secret-lease rows
/// (`secret_lease:v1:<lease_id_hex>`).
pub const SECRET_LEASE_KEY_PREFIX: &str = "secret_lease:v1:";

/// The `vault_meta` key prefix for T2 local-registration rows
/// (`secret_local:v1:<lease_id_hex>`).
///
/// SECRET-03 (ONE-1921) reads EVERY row under this prefix into the snapshot
/// exclusion set: a row is deleted only when the registered file is
/// verifiably gone, so any row still present names a path whose file may
/// hold the value.
pub const SECRET_LOCAL_REGISTRATION_PREFIX: &str = "secret_local:v1:";

/// The `vault_meta` key prefix for materialization-receipt rows
/// (`secret_lease_receipt:v1:<receipt_id_hex>`). Generic self-describing
/// receipt bodies — see the module docs' receipt-residence note.
pub const SECRET_MATERIALIZATION_RECEIPT_PREFIX: &str = "secret_lease_receipt:v1:";

/// The `kind` value stamped on materialization-receipt bodies.
pub const SECRET_MATERIALIZATION_RECEIPT_KIND: &str = "secret_materialization";

// ---------------------------------------------------------------------------
// The vault's authoritative instant
// ---------------------------------------------------------------------------

/// ONE reading of the vault's own authoritative clock.
///
/// The payload is private and this module is the only place that can put a
/// number into it: there is no `From<u64>`, no public constructor, and no
/// clock trait a caller could implement. Code outside `secret_lease` obtains
/// an instant from [`Vault::instant_in_txn`], reads it back through
/// [`VaultInstant::secs`], and may only move it FORWARD through
/// [`VaultInstant::after`].
///
/// That is the whole difference from the `now: u64` this replaces. A caller
/// that hands the credential door a number decides BY ITSELF whether a
/// credential sits inside its own lifetime — a slip that died an hour ago
/// authorizes perfectly against `now = issued_at`, and a slip whose remaining
/// validity is nearly spent buys a full-length ticket against `now =
/// issued_at` too. The instant this type admits was READ from the engine's
/// monotone observation clock instead, so "is this credential live, and how
/// much of it is left" is answered by the vault and never by whoever is
/// asking.
///
/// `Copy` on purpose: an instant is an OBSERVATION, not custody of anything,
/// and copying an observation cannot duplicate authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VaultInstant(pub(super) u64);

impl VaultInstant {
    /// The reading in unix seconds — for the durable row fields and for the
    /// external credential facts that are still spelled as numbers on the
    /// wire.
    pub(crate) fn secs(self) -> u64 {
        self.0
    }

    /// The instant `secs` AFTER this one.
    ///
    /// Forward-only, and deliberately the only arithmetic this type offers.
    /// It exists so a holder of a witnessed reading can name a DEADLINE
    /// derived from it — a credential live at `now` has its absolute expiry at
    /// exactly `now + remaining`, because `remaining` is
    /// `expires_at - now` — without any way to manufacture an EARLIER
    /// instant. An earlier instant is the dangerous direction: that is the one
    /// that makes a dead credential look live.
    pub(crate) fn after(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }
}

impl Vault {
    /// The vault's authoritative instant, read under `txn`.
    ///
    /// The single clock seam the credential door authorizes and stamps
    /// against. It is deliberately NOT the raw wall clock: it is the authority
    /// plane's monotone observation clock — the persisted first-seen clock
    /// floor read through `txn`, raised through
    /// [`authority_observation_secs`] — i.e. the same reading
    /// [`Vault::authority_fold`] and [`Vault::authority_fold_readonly_in_txn`]
    /// already make widen-maturity decisions on. Two vault answers that both
    /// turn on "has this window closed" therefore cannot disagree about what
    /// time it is.
    ///
    /// The observation is monotone within one vault handle and never sits below
    /// the persisted floor, so a wall clock stepped backwards cannot drag a
    /// door reading below a second this vault has already observed, and the
    /// anchor only ever advances by time it actually measured.
    ///
    /// Pure: it reads the persisted floor and returns. No cache, no epoch, no
    /// timer, and no write-back — the floor advances only on the authority
    /// write paths that already own it, which is why this can run inside a
    /// caller's read transaction at all.
    pub(crate) fn instant_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<VaultInstant> {
        let persisted_floor = self
            .store
            .sync_state
            .get(txn, authority_first_seen_clock_sync_key())?
            .and_then(|raw| decode_authority_first_seen_secs(&raw))
            .unwrap_or(0);
        Ok(VaultInstant(authority_observation_secs(
            &self.store,
            persisted_floor,
            unix_seconds_now(),
        )))
    }
}

// ---------------------------------------------------------------------------
// Lease status & rows
// ---------------------------------------------------------------------------

/// Lifecycle status of a [`SecretLease`]. Wire bytes mirror the
/// device-lease registry precedent (`sync::lease`): `0x01` active, `0x02`
/// expired, `0x03` revoked. Only `Active` admits use; `Revoked` is terminal
/// for the lease (a fresh materialization mints a fresh lease id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecretLeaseStatus {
    /// Live and usable within its tier.
    Active = 0x01,
    /// Past `expires_at` (lazy check at use, or the maintenance sweep).
    Expired = 0x02,
    /// Terminal. The only door-rejecting status besides `Expired`.
    Revoked = 0x03,
}

impl SecretLeaseStatus {
    /// The wire byte.
    #[must_use]
    pub const fn as_wire_byte(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte.
    #[must_use]
    pub fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Expired),
            0x03 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A T1/T2 lease row (`vault_meta` under [`SECRET_LEASE_KEY_PREFIX`]).
///
/// The row is the escalation ladder: a lease mints at `T1Leased` and climbs
/// to `T2LocalRegistered` when [`Vault::register_secret_local`] records the
/// local file under it. No `Serialize`/`Deserialize`: the engine's
/// [`EntityId`] has no serde form, and the MessagePack body codec below is
/// the ONE serialization of this row — it exists to write the vault-resident
/// body, nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLease {
    /// The lease identifier (minted by the vault at materialization).
    pub lease_id: EntityId,
    /// The secret name this lease was minted over.
    pub secret_ref: String,
    /// The effector the binding was resolved for at mint time.
    pub binding_effector: String,
    /// The highest rung this lease has reached (`T1Leased` |
    /// `T2LocalRegistered`).
    pub tier: CustodyTier,
    /// Unix seconds at mint.
    pub granted_at: u64,
    /// Unix seconds after which the lease is expired (`granted_at + ttl`).
    pub expires_at: u64,
    /// Lifecycle status.
    pub status: SecretLeaseStatus,
    /// The materialization receipt written durable BEFORE the value
    /// returned (S3).
    pub materialization_receipt: EntityId,
    /// The record's `rotation_generation` at mint (S6 staleness signal).
    pub value_generation: u32,
}

/// The T1 materialization return: the lease row plus the value.
///
/// The value is wrapped in [`Zeroizing`] so the caller's copy is scrubbed on
/// drop — the vault's side of the lease-scoped contract. `Debug` redacts
/// the value (`Zeroizing`'s own `Debug` would print the inner bytes).
#[derive(PartialEq, Eq)]
pub struct SecretLeaseMaterialization {
    /// The durable lease row.
    pub lease: SecretLease,
    /// The secret value (plaintext, zeroized on drop).
    pub value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SecretLeaseMaterialization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretLeaseMaterialization")
            .field("lease", &self.lease)
            .field(
                "value",
                &format_args!("<redacted {} bytes>", self.value.len()),
            )
            .finish()
    }
}

/// A T2 local registration (`vault_meta` under
/// [`SECRET_LOCAL_REGISTRATION_PREFIX`], keyed by lease id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRegistration {
    /// The lease this registration lives under.
    pub lease_id: EntityId,
    /// The manifest-declared local path holding the materialized value.
    pub path: PathBuf,
    /// BLAKE3 content hash of the materialized bytes (the
    /// `codebase.rs` `content_hash` convention SECRET-03 compares against).
    pub content_hash: [u8; 32],
    /// The project the path belongs to — SECRET-03's exclusion set reads
    /// this to scope exclusions per snapshot project.
    pub project_id: String,
}

/// The stored form of a local registration: the public row plus the
/// teardown record. A retained row with `removal_error` set is CLOSED (its
/// lease is torn down) but kept so the still-present file's path stays in
/// SECRET-03's exclusion set and the failure is recorded (best-effort,
/// recorded — never a silent drop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredLocalRegistration {
    pub(crate) registration: LocalRegistration,
    pub(crate) removal_error: Option<String>,
    pub(crate) removal_attempted_at: Option<u64>,
}

/// A taint reference for SECRET-04 (ONE-1922): declared here (layer 2)
/// because door/lease returns carry it; SECRET-04 consumes and invalidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTaintRef {
    /// The secret name.
    pub secret_ref: String,
    /// The record's rotation generation the value was read at.
    pub generation: u32,
}

/// The T0 door-injection receipt — the ONLY thing the workspace receives
/// from [`Vault::inject_secret_at_door`]. Carries no value bytes by
/// construction; `Debug` and serde are safe (grep-guard tested).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorInjectionReceipt {
    /// The secret name injected.
    pub secret_ref: String,
    /// The effector the binding was resolved for.
    pub effector: String,
    /// Unix seconds at injection (stamped at materialization, S3 —
    /// environment reads are not interceptable).
    pub injected_at: u64,
    /// The record's rotation generation the value was read at.
    pub value_generation: u32,
    /// SECRET-04 attaches exhaust taint from this token.
    pub taint_token: Vec<SecretTaintRef>,
}

/// The durable materialization receipt (`vault_meta` under
/// [`SECRET_MATERIALIZATION_RECEIPT_PREFIX`]). Written BEFORE the value
/// returns from [`Vault::materialize_secret_lease`]; carries no value
/// bytes. Generic receipt body: `kind =
/// `[`SECRET_MATERIALIZATION_RECEIPT_KIND`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMaterializationReceipt {
    /// The receipt identifier (referenced by
    /// [`SecretLease::materialization_receipt`]).
    pub receipt_id: EntityId,
    /// The secret name materialized.
    pub secret_ref: String,
    /// The effector the binding was resolved for.
    pub effector: String,
    /// The tier materialized at (`T1Leased` at mint).
    pub tier: CustodyTier,
    /// The lease this receipt attests.
    pub lease_id: EntityId,
    /// Unix seconds at materialization.
    pub materialized_at: u64,
    /// The record's rotation generation at materialization.
    pub value_generation: u32,
}
