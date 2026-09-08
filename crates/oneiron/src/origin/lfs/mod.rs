//! Vault-LFS: the Git-LFS object plane over the vault's EXISTING ASSET byte
//! plane (ARCH-0068 RA1, ONE-1909).
//!
//! The vault is the origin of git bytes. This module is the second concrete
//! bytes-in/bytes-out adapter beside [`super::smart_http`], and it deliberately
//! mints nothing new to be one:
//!
//! * every LFS byte is an ordinary [`ENTITY_TYPE_ASSET`] entity, so the
//!   standing batch pipeline — credential scan included — runs over it;
//! * the whole object plane is two ADDITIVE `vault_meta` prefix row families
//!   ([`VAULT_LFS_OBJECT_KEY_PREFIX`], [`VAULT_LFS_REF_KEY_PREFIX`]). No new
//!   entity type byte, no new named database, no new public storage primitive,
//!   no dependency;
//! * asset ids are deterministic through `entity_id_from_hash_material` over
//!   an LFS-only domain, so an LFS asset id can never collide with a
//!   blob-artifact or codebase asset id even for byte-identical content.
//!
//! # The two hash families coexist
//!
//! SHA-256 is the Git-LFS object id and therefore the dedup key HERE. BLAKE3
//! stays the frozen [`crate::blob_artifact::BlobArtifactVersion`] contract
//! THERE. Neither rewrites the other: they are different domains over different
//! prefixes, and this module never touches a `blob_artifact:` row.
//!
//! # Dedup is vault-scoped
//!
//! A vault is one tenant's sealed store. An object id computed from one
//! tenant's bytes never resolves storage for another, exactly as the
//! blob-artifact store already holds it.
//!
//! # Read paths fail closed
//!
//! [`Vault::get_lfs_object`] and [`Vault::verify_lfs_object`] re-check the
//! stored length AND re-hash the stored body before either answers. A body that
//! disagrees with its record is [`Error::CorruptedIndex`], never `Ok(bytes)` —
//! wrong bytes are not a successful download.
//!
//! # Admission is policy, never a size threshold
//!
//! [`LfsPathPolicy`] classifies a repository path; [`Vault::admit_lfs_pointer`]
//! turns that classification into an [`LfsAdmission`] and nothing else. The
//! caller enforces the outcome. There is NO automatic size threshold anywhere
//! in this module, and none may be added: a build-required asset is
//! build-required because of what it is, not because of how large it is.
//!
//! # What this module deliberately does not do
//!
//! No chunking (FastCDC stays deferred until measured duplication justifies
//! it). No transport: the HTTP surface lives in the server crate and calls
//! these entry points. No credential handling and no token format.

mod oid;
mod pointer;
mod policy;
mod store;

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

#[cfg(test)]
mod tests;

// The flat lfs.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every lfs-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::store::lfs_asset_entity_id;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_ASSET;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use sha2::{Digest, Sha256};
