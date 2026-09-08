//! ARTL-1 (OF-368 D1): versioned blob artifact store for foreign binary
//! (office) files.
//!
//! Rides the OF-320 bitemporal code-artifact shape instead of forking a
//! second artifact model:
//!
//! * the artifact is a typed entity
//!   ([`ENTITY_TYPE_BLOB_ARTIFACT`](crate::registry::ENTITY_TYPE_BLOB_ARTIFACT))
//!   whose body carries pinned metadata keys and never inline content;
//! * version bytes live in content-addressed
//!   ([`ENTITY_TYPE_ASSET`](crate::registry::ENTITY_TYPE_ASSET)) entities
//!   (blake3 content hash → deterministic asset id), so identical bytes are
//!   stored once per vault;
//! * each version is an append-only `vault_meta` record carrying the content
//!   hash, per-version provenance (user upload | agent-run ref), and the id
//!   of its `blob.version` claim — the LEDGER event for that version;
//! * history is append-only: a version is only ever added at head+1, and
//!   existing version records are never rewritten or deleted while the
//!   artifact lives. Re-appending the current head bytes is a dedupe no-op
//!   that returns the existing head version.
//!
//! Content-hash dedupe is vault-scoped ONLY. A vault is one tenant's sealed
//! store (OF-307): a content hash computed from one tenant's bytes never
//! resolves storage for another tenant, even when byte-identical.

mod body;
mod lifecycle;
mod provenance;
mod store_keys;
mod versions;

pub(crate) use self::body::validate_blob_artifact_body_bytes;
pub use self::body::{
    BLOB_ARTIFACT_BODY_KEYS, BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES, BLOB_ARTIFACT_NAME_MAX_BYTES,
    BLOB_ARTIFACT_OPTIONAL_BODY_KEYS, BlobArtifactBody, decode_blob_artifact_body,
    encode_blob_artifact_body,
};
pub(crate) use self::lifecycle::delete_blob_artifact_lifecycle_in_txn;
pub use self::provenance::BlobVersionProvenance;
pub(crate) use self::store_keys::require_entity_type;
pub use self::store_keys::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BLOB_ARTIFACT_RUN_REF_MAX_BYTES};
pub(crate) use self::versions::read_blob_artifact_head_in_txn;
pub use self::versions::{BLOB_ARTIFACT_VERSION_RECORD_KEYS, BlobArtifactVersion};

#[cfg(test)]
mod tests;

// The sibling `tests.rs` module resolves its bare names through `use super::*`:
// the one private blob-internal item the tests name
// (`blob_artifact_asset_entity_id`; every other blob name they use is
// re-exported above) plus the parent-scope crate/std imports the flat file
// used to provide. After the directory split the seam re-imports both so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::versions::blob_artifact_asset_entity_id;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;
