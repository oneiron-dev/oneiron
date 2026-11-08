//! Custody domain types: classes, tiers, bands, floors, bindings, records, and metadata.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::secret_record::{SECRET_SCOPE_READ, SecretBinding, SecretCustodyFloor, TierBand};
pub use oneiron_contracts::secret_custody::{CustodyClass, CustodyTier};

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
/// In memory, `value_bytes` is the opened value, which NEVER leaves this
/// record into claims / CRDT / export / receipts / logs. `Debug` redacts it.
/// At rest (stored schema 4, KS-6) the value is sealed under its
/// generation's erasable custody key (`storage_seal`); this record is the
/// opened form, stamped as its plaintext DTO is.
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
    /// Whether a model may receive plaintext through the reveal doors.
    /// Private copies keep this false independently of their class and bindings.
    pub model_reveal_allowed: bool,
    /// The secret value bytes (plaintext under the DEK plane; redacted in
    /// `Debug`; never serialized into logs/receipts/claims/CRDT).
    ///
    /// `pub(crate)`, not `pub`: a value read must go through the bound door
    /// [`Vault::get_secret_value_in_txn`] (which enforces the effector binding)
    /// rather than reaching the field directly on a decoded record. Within the
    /// crate the codec and doors move the bytes; out-of-crate there is no raw
    /// accessor at all — the value never crosses the crate boundary unbound.
    pub value_bytes: Vec<u8>,
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
    pub manifest_ref: String,
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
            .field("model_reveal_allowed", &self.model_reveal_allowed)
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

/// The body's MessagePack keys, in field order.
pub const SECRET_CUSTODY_BODY_KEYS: [&str; 14] = [
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
    "model_reveal_allowed",
];

/// The schema version of a record and of its plaintext DTO, the body with
/// its value in the clear under `value_bytes`: the owner archive's, a
/// register's protected input's and a transition's body; never a row at
/// rest, nor a checkpoint image's (KS-6 part 2). Version 3 requires the
/// record's model-reveal policy on every native reconstruction.
pub const SECRET_CUSTODY_SCHEMA_VERSION: u16 = 3;

/// The schema version a stored custody row is stamped with: its value sealed
/// under its generation's custody key, under `sealed_value`, and its required
/// model-reveal policy. Only the stored form takes it; a
/// record read from storage comes back stamped
/// [`SECRET_CUSTODY_SCHEMA_VERSION`], its DTO's.
pub const SECRET_CUSTODY_STORED_SCHEMA_VERSION: u16 = 4;

/// The `vault_meta` name-index key prefix mapping a live secret name to its
/// `EntityId` (`"vault_meta: name -> EntityId"`).
pub const SECRET_NAME_INDEX_PREFIX: &str = "secret_custody:name:v1:";

/// LMDB's key width: a key stops at 511 bytes.
const LMDB_KEY_BYTES: usize = 511;

/// The longest secret name, in bytes (ABC row 27): the name is the tail of
/// its name-index key, after [`SECRET_NAME_INDEX_PREFIX`], so it is LMDB's
/// key width less that prefix (488 bytes), derived, not a fixed 255.
pub const SECRET_NAME_MAX_BYTES: usize = LMDB_KEY_BYTES - SECRET_NAME_INDEX_PREFIX.len();
