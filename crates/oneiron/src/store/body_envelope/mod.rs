//! Body files and their instances (FIX 5348; KS-2A, FIX 5683 part A).
//!
//! Every body a vault keeps is one instance whose key typed custody holds
//! ([`custody`]), on either tier. A vault whose pages are sealed (the
//! maximum tier) keeps every body file it writes, a code-run result's and
//! an ASSET's alike, as an envelope under its instance's key, in E0 chunks
//! ([`frames`]); a vault whose pages are plain keeps plain body files, read
//! with no key. One `PROVENANCE_BODY_KEY` row per digest names the instance
//! ([`rows`]); it holds no key and no wrap of one, so no checkpoint that
//! carries it recovers a key.
//!
//! - A writer mints the instance outside any writer, stages the file under
//!   a name of its own (`<digest>-<instance>` when sealed) and commits the
//!   instance row, pinning the custody binding, in the transaction that
//!   writes the row or descriptor naming the body. A digest that already
//!   has a committed pair keeps it: the new file is an orphan for the
//!   collector, its instance unnamed debris.
//! - A reader of a sealed file resolves the instance row in the snapshot
//!   that found the body's row, under the custody read guard, and holds the
//!   opened key until it closes the file ([`BodyFile`]): whole, sequential
//!   and range reads each authenticate every chunk they touch first. A
//!   plain file's local read takes no key. No plaintext reaches a temp file.
//! - An off-record session's files are sealed under keys of their own,
//!   wrapped for the off-record scope in rows that stay in the session's
//!   overlay; promotion re-seals the body under a vault instance before the
//!   holder commits.
//! - The derived `.lines` index is sealed under a key of its own domain,
//!   derived from the file's key, and is never checkpointed.
//! - The collector that releases a body's final holder deletes its
//!   instance row in the same transaction and unlinks the file once no
//!   reader pins it; the key stays in custody (a delete keeps it, GC is never
//!   an erase). An erase retires it (`retention`).

mod custody;
mod frames;
mod opaque_response;
mod plan;
mod reader;
mod response;
mod retention;
mod retention_policy;
mod rows;
mod spill;

use std::sync::{Arc, PoisonError, RwLock};

use oneiron_crypto::Kek;
use zeroize::Zeroizing;

pub(crate) use self::custody::{
    BodyMint, body_key_in, body_mint_in, custody_unavailable, instance_id, pin_body_custody_in_txn,
};
pub(crate) use self::frames::{FileKey, SealedStream, SealingStream};
pub(crate) use self::opaque_response::{ResponseRead, ResponseScan};
pub(crate) use self::plan::{
    body_instances_in_rows, prune_retired_bodies_in_rows, require_body_instances,
};
pub(crate) use self::reader::BodyFile;
pub(crate) use self::response::{
    RESPONSE_BINDINGS, ResponseBinding, ResponseCarriage, ResponseDb, ResponseFamily,
    bind_response_in_txn, carrier_row, erase_response_owner_in_txn, release_response_in_txn,
    response_binding_in_txn, response_carrier, response_owed_to_all_in_txn,
    settle_shared_response_in_txn,
};
pub(crate) use self::retention::{
    INLINE_ASSETS, erase_bodies_for_owner_in_txn, erase_bodies_in_txn, note_settled_inline_in_txn,
    release_body_in_txn, settle_inline_asset_in_txn,
};
pub(crate) use self::rows::{
    BODY_KEYS, BodyKeyRow, bind_body_key_in_txn, body_key_row_in_txn,
    remember_body_instances_in_txn, retire_body_key_in_txn,
};
pub(crate) use self::spill::{
    BodySpill, SpilledBody, StagedBodyKey, keep_promoted_body_key_in_txn,
};
use super::{BodyDir, Store};
use crate::error::{Error, Result};

/// The context the body-file wrap key is derived under from the vault data
/// key.
pub(crate) const BODY_FILE_WRAP_CONTEXT: &str = "oneiron/body-file-wrap/v1";

/// How far retiring a body instance's key reaches (Engine 10-19, CALLS
/// "BODY_FILE_SHRED_SCOPE"; KS-2A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFileShredScope {
    /// Every instance's key rests in typed custody, outside every image: an
    /// erase's retirement reaches each kept copy, older checkpoints and
    /// backups included, which carry its bytes sealed under that key only.
    /// It is complete once every required custody target acknowledged it.
    EveryKeptCopy,
}

impl BodyFileShredScope {
    /// Whether a retirement reaches every kept copy, old checkpoints and
    /// backups included, so it may be reported complete.
    pub(crate) const fn reaches_kept_copies(self) -> bool {
        match self {
            Self::EveryKeptCopy => true,
        }
    }
}

/// CALLS "BODY_FILE_SHRED_SCOPE": what a body instance's key retirement
/// reaches.
pub(crate) const BODY_FILE_SHRED_SCOPE: BodyFileShredScope = BodyFileShredScope::EveryKeptCopy;

/// A sealed vault's body-file wrap key, with the vault id every wrap binds:
/// what an off-record session's file keys wrap under, in its overlay. In
/// memory only, wiped on drop, never printed; no vault row and no image
/// holds a wrap under it.
pub(crate) struct BodySeal {
    vault_id: [u8; 32],
    wrap: Kek,
}

impl std::fmt::Debug for BodySeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BodySeal(..)")
    }
}

impl BodySeal {
    /// The seal of vault `vault_id` under `wrap`, the subkey for
    /// [`BODY_FILE_WRAP_CONTEXT`] of its data key.
    pub(crate) fn new(vault_id: [u8; 32], wrap: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            vault_id,
            wrap: Kek::from_bytes_ref(wrap),
        }
    }
}

/// The body-file seal a sealed vault's store holds once its data key is
/// admitted at open. Empty on a plain vault.
#[derive(Default)]
pub(crate) struct BodySealSlot(RwLock<Option<Arc<BodySeal>>>);

impl BodySealSlot {
    /// Holds `seal` for every handle on this store.
    pub(crate) fn admit(&self, seal: BodySeal) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(seal));
    }

    fn get(&self) -> Option<Arc<BodySeal>> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Whose key rows a body directory's files are wrapped for: the vault's, or
/// an off-record session's, whose rows stay in its overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyScope {
    Vault,
    OffRecord,
}

impl KeyScope {
    /// The recipient a wrap of this scope binds.
    const fn recipient(self) -> &'static [u8] {
        match self {
            Self::Vault => b"oneiron/body-file/vault",
            Self::OffRecord => b"oneiron/body-file/off-record",
        }
    }
}

/// A sealed vault's body directory: its scope; the seal an off-record
/// session's keys wrap under, absent until the vault's data key is admitted
/// (every off-record write and read through it fails closed until then);
/// and the custody binding a vault directory's instance keys are read
/// under, absent until the vault's first publication.
#[derive(Clone)]
pub(crate) struct DirSeal {
    scope: KeyScope,
    seal: Option<Arc<BodySeal>>,
    custody: Option<crate::store::key_custody::CustodyBinding>,
}

impl DirSeal {
    fn seal(&self) -> Result<&BodySeal> {
        self.seal.as_deref().ok_or_else(|| {
            crate::world_keys::refused("a sealed vault's body-file key is not admitted")
        })
    }
}

/// `<digest>-<instance>`: a sealed body file's name. The instance is the
/// file's own, so a body written again under a fresh key never takes the
/// name of a file a reader may still hold.
pub(crate) fn sealed_body_file_name(digest: &[u8; 32], instance: &[u8; 16]) -> String {
    format!(
        "{}-{}",
        super::body_file_name(digest),
        crate::entity_id::bytes_to_hex_lower(instance)
    )
}

impl Store {
    /// The seal a body directory of this store in `scope` carries: `None`
    /// on a vault whose pages are plain.
    pub(crate) fn dir_seal(&self, scope: KeyScope) -> Option<DirSeal> {
        heed::Env::is_sealed(&self.env).then(|| DirSeal {
            scope,
            seal: self.body_seal.get(),
            custody: self.body_custody(),
        })
    }

    /// Whether this vault's `bodies/` holds the body `digest` of `len`
    /// bytes, as the key row a fresh snapshot holds names it: a probe for a
    /// caller that holds no snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors, and a key that does not open.
    pub(crate) fn body_file_present(&self, digest: &[u8; 32], len: u64) -> Result<bool> {
        // Before the snapshot, through the key's use (FIX 6019).
        let _custody = self.core.key_custody.read_guard()?;
        let row = {
            let rtxn = self.env.read_txn()?;
            body_key_row_in_txn(self, &rtxn, digest)?
        };
        Ok(self
            .body_dir()?
            .open_reader(digest, len, row.as_ref())?
            .is_some())
    }
}

impl BodyDir {
    /// The body `digest` of `len` bytes, as `row` (its instance row, read in
    /// the snapshot that found the body's row) names it: in a sealed
    /// directory an envelope read through its instance's key, in a plain one
    /// the plain file, whatever its row, read with no key. `None` when this
    /// directory does not hold it, or the row is another scope's.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a file of another length or a frame
    /// that does not open; filesystem errors as they occur.
    pub(crate) fn open_reader(
        &self,
        digest: &[u8; 32],
        len: u64,
        row: Option<&BodyKeyRow>,
    ) -> Result<Option<BodyFile>> {
        let (Some(sealed), Some(row)) = (&self.sealed, row) else {
            return Ok(self
                .open_body(digest, len)?
                .map(|file| BodyFile::plain(file, len)));
        };
        if row.len != len {
            return Err(Error::CorruptedIndex("body file key length"));
        }
        let Some(key) = row.open(digest, sealed)? else {
            return Ok(None);
        };
        let Some(file) = self.open_named(&sealed_body_file_name(digest, &row.instance))? else {
            return Ok(None);
        };
        BodyFile::sealed(file, key, digest, len).map(Some)
    }

    /// Reads the file of the body `digest` back whole under `binding`'s
    /// custody, as its instance row `row` names it (an activation's read
    /// back, FIX 6020): a sealed directory's envelope frame by frame under
    /// the instance's key, a plain one's body against its digest, with the
    /// instance's key read too, since a plain read takes none.
    ///
    /// # Errors
    ///
    /// `body_key_custody_unavailable` for a key custody does not hold;
    /// [`Error::CorruptedIndex`] for a file missing, of another length, or
    /// that does not open or check; filesystem errors.
    pub(crate) fn read_back(
        &self,
        binding: &crate::store::key_custody::CustodyBinding,
        digest: &[u8; 32],
        row: &BodyKeyRow,
    ) -> Result<()> {
        let key = body_key_in(binding, &row.instance)?;
        let missing = || Error::CorruptedIndex("body file missing at read back");
        let mut file = if self.sealed.is_some() {
            let file = self
                .open_named(&sealed_body_file_name(digest, &row.instance))?
                .ok_or_else(missing)?;
            BodyFile::sealed(file, key, digest, row.len)?
        } else {
            BodyFile::plain(
                self.open_body(digest, row.len)?.ok_or_else(missing)?,
                row.len,
            )
        };
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        if hasher.finalize().as_bytes() != digest {
            return Err(Error::CorruptedIndex("body file does not match its digest"));
        }
        Ok(())
    }

    /// Whether `row`, the instance row of the body `digest`, is a committed
    /// pair in this directory: a file row of its scope, its file here (a
    /// sealed directory's under the row's instance, a plain one's under the
    /// digest).
    ///
    /// # Errors
    ///
    /// A row that does not parse, and filesystem errors.
    pub(crate) fn holds_pair(&self, digest: &[u8; 32], row: Option<&BodyKeyRow>) -> Result<bool> {
        let Some(row) = row.filter(|row| !row.inline) else {
            return Ok(false);
        };
        let Some(sealed) = &self.sealed else {
            return Ok(self.open_named(&super::body_file_name(digest))?.is_some());
        };
        Ok(row.wrapped_for(sealed.scope)?
            && self
                .open_named(&sealed_body_file_name(digest, &row.instance))?
                .is_some())
    }

    /// The sparse line index of the body `digest`, `len` bytes long, as
    /// `row` names it: the sealed index of an envelope, or the plain one.
    /// `None` when there is none, or it does not read whole: it is derived.
    pub(crate) fn line_index_of(
        &self,
        digest: &[u8; 32],
        len: u64,
        row: Option<&BodyKeyRow>,
    ) -> Option<Vec<u64>> {
        let (Some(row), Some(sealed)) = (row, &self.sealed) else {
            return self.read_line_index(digest, len);
        };
        let key = row.open(digest, sealed).ok()??;
        let file = self
            .open_named(&format!(
                "{}{}",
                sealed_body_file_name(digest, &row.instance),
                super::LINE_INDEX_SUFFIX
            ))
            .ok()??;
        frames::read_line_index(file, &key, len)
    }
}
