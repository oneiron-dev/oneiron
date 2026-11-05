//! Secret custody record vocabulary, body codecs, and stored policy-floor resolution.

pub use crate::secret_record::codec::CUSTODY_SEAL_REASON;
pub use crate::secret_record::codec::encode_secret_custody_body;
pub use crate::secret_record::codec::reject_secret_custody_byte;
pub use crate::secret_record::types::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
pub use crate::secret_record::types::*;

/// MessagePack keys the custody floor reads out of POLICY_MANIFEST bodies.
pub mod floor_keys {
    pub const PORTABLE_MIN: &str = "secret.custody.floor.portable.min";
    pub const PORTABLE_MAX: &str = "secret.custody.floor.portable.max";
    pub const DEVICE_BOUND_MIN: &str = "secret.custody.floor.device_bound.min";
    pub const DEVICE_BOUND_MAX: &str = "secret.custody.floor.device_bound.max";
    pub const CROSS_VAULT_MIN: &str = "secret.custody.floor.cross_vault.min";
    pub const CROSS_VAULT_MAX: &str = "secret.custody.floor.cross_vault.max";
    pub const ROTATION_MAX_AGE_SECS: &str = "secret.custody.rotation_max_age_secs";
    pub const ENV_BINDINGS: &str = "secret.custody.env_bindings";
}

pub mod write_records;

pub use crate::secret_record::write_records::ArchiveSameId;
pub use crate::secret_record::write_records::CustodyKeptHere;
pub use crate::secret_record::write_records::CustodyPlan;
pub use crate::secret_record::write_records::FoundKeyAction;
pub use crate::secret_record::write_records::FoundKeySettled;
pub use crate::secret_record::write_records::FoundNote;
pub use crate::secret_record::write_records::StoredValue;

pub use crate::secret_record::write_records::SLOT_PREFIX;
pub use crate::secret_record::write_records::custody_portable;
pub use crate::secret_record::write_records::is_cloud_registration_slot;

pub use crate::secret_record::write_records::RepoFileKeys;
pub use crate::secret_record::write_records::RepoFileOriginal;

pub mod codec;
pub mod types;
