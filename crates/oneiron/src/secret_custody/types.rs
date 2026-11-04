//! Custody record vocabulary, defined in the store layer.

pub(super) use crate::secret_record::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
pub use crate::secret_record::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SECRET_NAME_INDEX_PREFIX, SECRET_NAME_MAX_BYTES, SECRET_SCOPE_READ, SecretBinding,
    SecretCustodyFloor, SecretCustodyMetadata, SecretCustodyRecord, SecretCustodyStatus, TierBand,
};
