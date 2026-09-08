//! Custody domain types: classes, tiers, bands, floors, bindings, records, and metadata.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Custody classes & tiers
// ---------------------------------------------------------------------------

/// ARCH-0069 S1 custody classes. Wire strings are canon nouns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyClass {
    /// The value may replicate beyond this device (the default reach).
    CustodyPortable,
    /// The value is pinned to this device (device-pin locality posture under
    /// slip authority — not a hardware/device custody tier).
    CustodyDeviceBound,
    /// Door-only: the value never replicates at all.
    CrossVault,
}

impl CustodyClass {
    /// The canon kebab-case wire noun.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustodyPortable => "custody-portable",
            Self::CustodyDeviceBound => "custody-device-bound",
            Self::CrossVault => "cross-vault",
        }
    }

    /// Parses the canon kebab-case wire noun.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "custody-portable" => Some(Self::CustodyPortable),
            "custody-device-bound" => Some(Self::CustodyDeviceBound),
            "cross-vault" => Some(Self::CrossVault),
            _ => None,
        }
    }
}

/// SECRET-02 owns tier mechanics; the enum is declared here because
/// [`SecretBinding`]s and [`SecretCustodyFloor`] name it.
///
/// Ordering is exposure of the secret VALUE: `T0Doored < T1Leased <
/// T2LocalRegistered`. `T0` is always the least-exposed bound. Authority is
/// never tier-shaped: the custody principal is the host-minted capability
/// slip (OF-452 D1/D7), not a device tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CustodyTier {
    /// Least exposed: value only reachable at the door.
    T0Doored,
    /// Value reachable under a lease.
    T1Leased,
    /// Value reachable as a locally-registered reference.
    T2LocalRegistered,
}

impl CustodyTier {
    /// The integer wire grade (`T0`=0 … `T2`=2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::T0Doored => 0,
            Self::T1Leased => 1,
            Self::T2LocalRegistered => 2,
        }
    }

    /// Parses from the integer wire grade.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::T0Doored),
            1 => Some(Self::T1Leased),
            2 => Some(Self::T2LocalRegistered),
            _ => None,
        }
    }
}

/// Per-class allowed tier band (inclusive). Floors narrow the `max` (the most
/// exposure a class may reach), never force exposure — `min` is informational
/// (and `T0Doored` by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierBand {
    /// Least-exposed tier in the band (informational).
    pub min: CustodyTier,
    /// Most-exposed tier the class may reach under this band.
    pub max: CustodyTier,
}

impl TierBand {
    /// A band spanning a single tier.
    #[must_use]
    pub const fn only(tier: CustodyTier) -> Self {
        Self {
            min: tier,
            max: tier,
        }
    }

    /// True when `tier` sits inside this band (inclusive).
    #[must_use]
    pub fn admits(&self, tier: CustodyTier) -> bool {
        self.min <= tier && tier <= self.max
    }

    /// The narrower of two bands (most-restrictive merge).
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            min: self.min.max(other.min),
            max: self.max.min(other.max),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved vault custody floor
// ---------------------------------------------------------------------------

/// The vault's custody floor, resolved from the `secret.custody.*` keys in
/// POLICY_MANIFEST bodies (DEC-0005: floors live in the vault's policy
/// manifests; callers narrow, never widen). Most-restrictive wins per field
/// across packs.
///
/// The tiers grade exposure of the secret VALUE (never a device tier) —
/// under host-root there is no device tier to be "custodial" against; the
/// authority principal is the capability slip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyFloor {
    /// Allowed tier band for `custody-portable` (default `T0..T2`).
    pub portable: TierBand,
    /// Allowed tier band for `custody-device-bound` (default `T0..T2`).
    pub device_bound: TierBand,
    /// Allowed tier band for `cross-vault` (default `T0..T0`, door-only).
    pub cross_vault: TierBand,
    /// Maximum age before a value must be rotated (None = no floor).
    pub rotation_max_age_secs: Option<u64>,
    /// Environment bindings (e.g. `prod` → restriction note), narrowed on
    /// conflicting values.
    pub env_bindings: BTreeMap<String, String>,
}

impl Default for SecretCustodyFloor {
    fn default() -> Self {
        Self {
            portable: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            device_bound: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            cross_vault: TierBand::only(CustodyTier::T0Doored),
            rotation_max_age_secs: None,
            env_bindings: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Bindings, status, record, metadata
// ---------------------------------------------------------------------------

/// The scope verb a binding must declare before the value door will hand over
/// plaintext. Scopes are otherwise free-form: they name what a binding is FOR,
/// and only this one is load-bearing at a door.
pub const SECRET_SCOPE_READ: &str = "read";

/// A binding scoping which effector may use a secret ref, at what tier
/// ceiling. The binding check scopes usage, drives tier admission, and
/// stamps receipts. No binding covering `(secret_ref, effector)` with the
/// required scope ⇒ [`Error::SecretBindingDenied`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    /// The effector, e.g. `"connector:gmail"`, `"door:receive-pack"`.
    pub effector: String,
    /// The most-exposed tier this binding may request.
    pub tier_ceiling: CustodyTier,
    /// Declared scopes the binding covers.
    pub scopes: Vec<String>,
}

impl SecretBinding {
    /// Whether this binding carries the [`SECRET_SCOPE_READ`] grant the value
    /// door requires.
    ///
    /// An EMPTY scope list is NOT a wildcard. Reading it as one is how a
    /// declared-but-unenforced field becomes a hole: every binding written
    /// before scopes meant anything would silently grant plaintext reads. A
    /// binding that declares no scope grants no read.
    #[must_use]
    pub fn grants_read(&self) -> bool {
        self.scopes.iter().any(|s| s == SECRET_SCOPE_READ)
    }
}

/// Lifecycle status of a custody record. Only `Active` records are usable;
/// a `Revoked` name frees for re-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretCustodyStatus {
    /// Live and usable within its bindings.
    Active,
    /// Temporarily unusable; name still held.
    Suspended,
    /// Terminal; the name frees for re-registration.
    Revoked,
}

impl SecretCustodyStatus {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Parses the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Entity body for `ENTITY_TYPE_SECRET_CUSTODY`: the secret value's home.
///
/// `value_bytes` is plaintext under the vault DEK plane and NEVER leaves this
/// body into claims / CRDT / export / receipts / logs. `Debug` redacts it.
/// `policy_floor_snapshot` records the floor at register time for audit;
/// `manifest_ref` + `declared_paths` are copied from the manifest entry so
/// downstream consumers (SECRET-03, snapshot exclusion) have a vault-side
/// data source.
/// No `Serialize`/`Deserialize`: a derived serializer would emit `value_bytes`
/// into whatever format a caller reached for (JSON log line, receipt, wire
/// payload) with no door in the way — the same leak `Debug` is hand-rolled to
/// prevent. The body codec below is the ONE serialization of this type, and it
/// exists to write the vault-resident body, nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretCustodyRecord {
    /// Body schema version (`SECRET_CUSTODY_SCHEMA_VERSION` at encode).
    pub schema_version: u16,
    /// Unique-per-vault secret name; see [`SECRET_NAME_INDEX_PREFIX`].
    pub name: String,
    /// The custody class — the value-exposure posture.
    pub class: CustodyClass,
    /// The OF-422 portable dial. Stored as data from day one so ONE-1865
    /// needs no migration; enforcement (replication locality) is ONE-1865's.
    /// On a `cross-vault` record this is stored-but-inert.
    pub device_only: bool,
    /// The secret value bytes (plaintext under the DEK plane; redacted in
    /// `Debug`; never serialized into logs/receipts/claims/CRDT).
    ///
    /// `pub(crate)`, not `pub`: a value read must go through the bound door
    /// [`Vault::get_secret_value_in_txn`] (which enforces the effector binding)
    /// rather than reaching the field directly on a decoded record. Within the
    /// crate the codec and doors move the bytes; out-of-crate there is no raw
    /// accessor at all — the value never crosses the crate boundary unbound.
    pub(crate) value_bytes: Vec<u8>,
    /// Lifecycle status.
    pub status: SecretCustodyStatus,
    /// Unix seconds at registration.
    pub registered_at: u64,
    /// Unix seconds of the last rotation (SECRET-04 stamps it).
    pub rotated_at: Option<u64>,
    /// Rotation generation counter.
    pub rotation_generation: u32,
    /// Effector bindings on this record.
    pub bindings: Vec<SecretBinding>,
    /// The manifest path this entry was registered from (empty when
    /// registered outside a manifest flow). Read via [`Self::manifest_ref`];
    /// `pub(crate)` keeps the struct's serde/codec construction inside the
    /// crate while exposing only a read-only reference outward.
    pub(crate) manifest_ref: String,
    /// Declared secret paths copied from the manifest entry (SECRET-03).
    pub declared_paths: Vec<String>,
    /// The resolved vault floor at register time (audit).
    pub policy_floor_snapshot: SecretCustodyFloor,
}

// Deliberately hand-rolled: never print `value_bytes` (S1). The grep-guard
// test asserts `value_bytes` does not appear in the Debug output.
impl fmt::Debug for SecretCustodyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCustodyRecord")
            .field("schema_version", &self.schema_version)
            .field("name", &self.name)
            .field("class", &self.class)
            .field("device_only", &self.device_only)
            .field(
                "value_bytes",
                &format_args!("<redacted {} bytes>", self.value_bytes.len()),
            )
            .field("status", &self.status)
            .field("registered_at", &self.registered_at)
            .field("rotated_at", &self.rotated_at)
            .field("rotation_generation", &self.rotation_generation)
            .field("bindings", &self.bindings)
            .field("manifest_ref", &self.manifest_ref)
            .field("declared_paths", &self.declared_paths)
            .field("policy_floor_snapshot", &self.policy_floor_snapshot)
            .finish()
    }
}

/// The value-less projection — the ONLY read most callers get. Has no value
/// field by construction (type-level proof of S1's read-plane discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyMetadata {
    /// The secret name.
    pub name: String,
    /// The custody class.
    pub class: CustodyClass,
    /// Lifecycle status.
    pub status: SecretCustodyStatus,
    /// Unix seconds at registration.
    pub registered_at: u64,
    /// Unix seconds of the last rotation.
    pub rotated_at: Option<u64>,
    /// Rotation generation counter.
    pub rotation_generation: u32,
    /// Effector bindings.
    pub bindings: Vec<SecretBinding>,
}

impl SecretCustodyRecord {
    /// Projects to the value-less metadata read.
    #[must_use]
    pub fn metadata(&self) -> SecretCustodyMetadata {
        SecretCustodyMetadata {
            name: self.name.clone(),
            class: self.class,
            status: self.status,
            registered_at: self.registered_at,
            rotated_at: self.rotated_at,
            rotation_generation: self.rotation_generation,
            bindings: self.bindings.clone(),
        }
    }

    /// Looks up the binding covering `effector`. Drives tier admission.
    #[must_use]
    pub fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }

    /// The manifest path this entry was registered from — the read-only,
    /// binding-door-safe view of `manifest_ref` for out-of-crate consumers
    /// (SECRET-03 snapshot exclusion reads it from the record's body decode).
    /// Empty when the record was registered outside a manifest flow.
    #[must_use]
    pub fn manifest_ref(&self) -> &str {
        &self.manifest_ref
    }
}

// ---------------------------------------------------------------------------
// Body codec — a MessagePack key map named by SECRET_CUSTODY_BODY_KEYS
// ---------------------------------------------------------------------------

/// The body's MessagePack keys, in field order. `13 keys = 13 fields`.
pub const SECRET_CUSTODY_BODY_KEYS: [&str; 13] = [
    "schema_version",
    "name",
    "class",
    "device_only",
    "value_bytes",
    "status",
    "registered_at",
    "rotated_at",
    "rotation_generation",
    "bindings",
    "manifest_ref",
    "declared_paths",
    "policy_floor_snapshot",
];

/// The body schema version stamped at encode time.
pub const SECRET_CUSTODY_SCHEMA_VERSION: u16 = 1;

/// The `vault_meta` name-index key prefix mapping a live secret name to its
/// `EntityId` (`"vault_meta: name -> EntityId"`).
pub const SECRET_NAME_INDEX_PREFIX: &str = "secret_custody:name:v1:";
