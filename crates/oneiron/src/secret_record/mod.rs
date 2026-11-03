//! Secret custody record vocabulary, body codecs, and stored policy-floor resolution.

pub(crate) mod codec;
pub(crate) mod floor;
mod types;

pub(crate) use self::codec::{CUSTODY_SEAL_REASON, reject_secret_custody_byte};
pub use self::codec::{decode_secret_custody_body, encode_secret_custody_body};
pub(crate) use self::floor::{PolicyManifestWalkError, policy_manifest_bodies_strict};
pub(crate) use self::types::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
pub use self::types::*;

/// MessagePack keys the custody floor reads out of POLICY_MANIFEST bodies.
pub(crate) mod floor_keys {
    pub(crate) const PORTABLE_MIN: &str = "secret.custody.floor.portable.min";
    pub(crate) const PORTABLE_MAX: &str = "secret.custody.floor.portable.max";
    pub(crate) const DEVICE_BOUND_MIN: &str = "secret.custody.floor.device_bound.min";
    pub(crate) const DEVICE_BOUND_MAX: &str = "secret.custody.floor.device_bound.max";
    pub(crate) const CROSS_VAULT_MIN: &str = "secret.custody.floor.cross_vault.min";
    pub(crate) const CROSS_VAULT_MAX: &str = "secret.custody.floor.cross_vault.max";
    pub(crate) const ROTATION_MAX_AGE_SECS: &str = "secret.custody.rotation_max_age_secs";
    pub(crate) const ENV_BINDINGS: &str = "secret.custody.env_bindings";
}

pub(crate) mod admission;
pub(crate) mod carrier_marks;
mod write_records;

pub(crate) use self::admission::{SecretCustodyAdmission, read_secret_custody_admission_in_txn};
pub(crate) use self::carrier_marks::{CarrierMark, carrier_mark_in_txn, put_carrier_mark_in_txn};
pub(crate) use self::write_records::{ArchiveSameId, CustodyWrite, FoundNote, StoredValue};
pub use self::write_records::{CustodyKeptHere, CustodyPlan, FoundKeyAction, FoundKeySettled};

pub(crate) use self::write_records::{SLOT_PREFIX, custody_portable, is_cloud_registration_slot};

pub(crate) use self::write_records::{RepoFileKeys, RepoFileOriginal};
