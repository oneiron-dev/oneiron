//! Custody domain types: classes, tiers, bands, floors, bindings, status and metadata.
//! The custody record itself stays in the engine (`oneiron::secret_record`), so its
//! value field stays crate-private there.

use serde::{Deserialize, Serialize};

pub use crate::secret_record::{SECRET_SCOPE_READ, SecretBinding, SecretCustodyFloor, TierBand};
pub use oneiron_contracts::secret_custody::{CustodyClass, CustodyTier};

/// Lifecycle status of a custody record. Only `Active` records are usable;
/// a `Revoked` name frees for re-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretCustodyStatus {
    /// Live and usable within its bindings.
    Active,
    /// Terminal; the name frees for re-registration.
    Revoked,
}

impl SecretCustodyStatus {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
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
