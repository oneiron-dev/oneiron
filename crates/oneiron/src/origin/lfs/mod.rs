//! Vault-scoped FastCDC/BLAKE3 object plane over ordinary ASSET storage.
//!
//! Git-LFS SHA-256 remains the pointer wire format only. Byte dedup uses
//! BLAKE3 chunk ids and canonical BLAKE3 manifests. Per-vault random gear
//! parameters produce stable 32/64/128 KiB boundaries without cross-vault
//! parameter sharing. Streaming IO holds bounded byte buffers, not whole files.
//!
//! Manifests publish only after size, digest and credential admission. Chunk
//! references are journaled and reclaimed in small transactions. Explicit
//! object deletion is permanent; detaching a Git ref never destroys bytes.

mod chunks;
mod lifecycle;
mod oid;
mod pointer;
mod policy;
mod scanner;
mod store;
mod upload;

pub use self::chunks::{
    LFS_CHUNK_AVG, LFS_CHUNK_MAX, LFS_CHUNK_MIN, LfsChunkParameters, LfsChunkRef, LfsManifest,
};
pub use self::oid::{LfsOid, VAULT_LFS_OID_HEX_LEN, VAULT_LFS_OID_LEN};
pub use self::pointer::{LfsPointerIntent, LfsPushedPointer};
pub use self::policy::{
    DefaultRepositoryLargeLfsPathPolicy, LfsAdmission, LfsAssetClass, LfsPathPolicy,
};
pub use self::store::{
    LFS_BASIC_TRANSFER, LFS_JSON_MEDIA_TYPE, LfsPutOutcome, VAULT_LFS_ASSET_ID_DOMAIN,
    VAULT_LFS_OBJECT_KEY_PREFIX, VAULT_LFS_REF_KEY_PREFIX, VAULT_LFS_REPO_ID_DOMAIN,
    VAULT_LFS_SCHEMA_VERSION, VaultLfsObject, check_lfs_expectation, lfs_repo_id,
};
pub(crate) use lifecycle::{
    delete_lfs_lifecycle_in_txn, guard_lfs_asset_put, reject_direct_lfs_chunk_delete,
};
#[cfg(feature = "sync")]
pub(crate) use lifecycle::{is_lfs_chunk_asset_in_txn, is_lfs_chunk_blob};

#[cfg(test)]
mod chunk_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_ASSET;
#[cfg(test)]
use crate::{EntityId, TimeRange, Vault};
#[cfg(test)]
use sha2::{Digest, Sha256};
