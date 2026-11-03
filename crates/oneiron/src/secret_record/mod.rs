//! Secret custody record vocabulary, body codecs, and stored policy-floor resolution.

pub(crate) mod codec;
pub(crate) mod floor;
mod types;

pub use self::types::*;
pub(crate) use self::types::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
pub use self::codec::{decode_secret_custody_body, encode_secret_custody_body};
pub(crate) use self::codec::{CUSTODY_SEAL_REASON, reject_secret_custody_byte};
pub(crate) use self::floor::{PolicyManifestWalkError, policy_manifest_bodies_strict};

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
