//! Core half of `secret_record`: its store-layer items live in `oneiron_store::secret_record` and are
//! re-exported here; the items below stay in the engine, among them the custody
//! record, whose value and manifest reference are crate-private.

pub use oneiron_store::secret_record::*;

pub(crate) use self::admission::{SecretCustodyAdmission, read_secret_custody_admission_in_txn};
pub(crate) use self::carrier_marks::{CarrierMark, carrier_mark_in_txn, put_carrier_mark_in_txn};
pub(crate) use self::codec::{CUSTODY_SEAL_REASON, reject_secret_custody_byte};
pub use self::codec::{decode_secret_custody_body, encode_secret_custody_body};
pub(crate) use self::floor::{PolicyManifestWalkError, policy_manifest_bodies_strict};
pub(crate) use self::types::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
pub use self::types::SecretCustodyRecord;
pub(crate) use self::write_records::{ArchiveSameId, CustodyWrite, FoundNote, StoredValue};
pub use self::write_records::{CustodyKeptHere, CustodyPlan, FoundKeyAction, FoundKeySettled};
pub(crate) use self::write_records::{RepoFileKeys, RepoFileOriginal};
pub(crate) use self::write_records::{SLOT_PREFIX, custody_portable, is_cloud_registration_slot};

pub(crate) mod admission;
pub(crate) mod carrier_marks;
pub(crate) mod codec;
pub(crate) mod floor;
pub(crate) mod tables;
mod types;
mod write_records;
