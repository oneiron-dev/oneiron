//! Body files on a sealed vault (FIX 5348, L01 FIX 3677 follow-up).
//!
//! A vault whose pages are sealed (the maximum tier) keeps every body file
//! it writes, a code-run result's and an ASSET's alike, as an envelope: the
//! file's own random data key seals it in E0 chunks ([`frames`]), and that
//! key rests only wrapped, under the vault's body-file wrap key
//! (`oneiron/body-file-wrap/v1`, derived from the vault data key, never the
//! page key), in one `PROVENANCE_BODY_KEY` row per digest ([`rows`]). A
//! sealed vault holds its data key from the moment it opens, so this adds no
//! unlock; a vault whose pages are plain keeps plain body files, as before.
//!
//! - A writer stages the ciphertext under a name of its own,
//!   `<digest>-<instance>`, and commits the key row in the transaction that
//!   writes the row or descriptor naming the body. A digest that already has
//!   a committed pair keeps it: the new file is an orphan for the collector,
//!   and no committed file is ever overwritten with fresh-key ciphertext.
//! - A reader resolves the key row in the snapshot that found the body's
//!   row and holds the opened key until it closes the file ([`BodyFile`]):
//!   whole reads, sequential reads and range reads each authenticate every
//!   chunk they touch before returning a byte of it. No plaintext reaches a
//!   temp file.
//! - An off-record session's files wrap their keys for the off-record scope
//!   and their rows stay in the session's overlay; promotion copies the
//!   ciphertext and rewraps the key for the vault before the holder commits.
//! - The derived `.lines` index is sealed under a key of its own domain,
//!   derived from the file's data key, and is never checkpointed.
//! - The collector that releases a body's final holder deletes its key row
//!   in the same transaction, then unlinks the file once no reader pins it
//!   ([`BODY_FILE_SHRED_SCOPE`]: the live vault only).

mod frames;
mod reader;
mod rows;
mod spill;

use std::sync::{Arc, PoisonError, RwLock};

use oneiron_crypto::Kek;
use zeroize::Zeroizing;

pub(crate) use self::frames::SealedStream;
pub(crate) use self::reader::BodyFile;
pub(crate) use self::rows::{
    BODY_KEYS, BodyKeyRow, bind_body_key_in_txn, body_key_row_in_txn, retire_body_key_in_txn,
};
pub(crate) use self::spill::{
    BodySpill, SpilledBody, StagedBodyKey, keep_promoted_body_key_in_txn,
};
use super::{BodyDir, Store};
use crate::error::{Error, Result};

/// The context the body-file wrap key is derived under from the vault data
/// key.
pub(crate) const BODY_FILE_WRAP_CONTEXT: &str = "oneiron/body-file-wrap/v1";

/// How far retiring a body file's key reaches (Engine 10-19, CALLS
/// "BODY_FILE_SHRED_SCOPE", open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFileShredScope {
    /// The live vault's key row and file go when the final holder is
    /// released. A checkpoint image or backup taken before keeps its copy of
    /// both until it ages out; reaching those needs the key outside every
    /// checkpoint artifact (exterior custody, the owner's card).
    LiveVaultUntilExteriorCustody,
}

impl BodyFileShredScope {
    /// Whether a retirement reaches every kept copy, old checkpoints and
    /// backups included, so it may be reported complete.
    pub(crate) const fn reaches_kept_copies(self) -> bool {
        match self {
            Self::LiveVaultUntilExteriorCustody => false,
        }
    }
}

/// FIX 5348 (CALLS "BODY_FILE_SHRED_SCOPE"): what a body file's key
/// retirement reaches.
pub(crate) const BODY_FILE_SHRED_SCOPE: BodyFileShredScope =
    BodyFileShredScope::LiveVaultUntilExteriorCustody;

/// A sealed vault's body-file wrap key, with the vault id every wrap and
/// chunk binds. In memory only, wiped on drop, never printed.
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
            wrap: Kek::from_bytes(**wrap),
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

/// A sealed vault's body directory: its scope, and the seal its keys wrap
/// under, which is absent until the vault's data key is admitted. Every
/// write and read through it fails closed while the seal is absent.
#[derive(Clone)]
pub(crate) struct DirSeal {
    scope: KeyScope,
    seal: Option<Arc<BodySeal>>,
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
    /// The body `digest` of `len` bytes, as `row` (its key row, read in the
    /// snapshot that found the body's row) names it: an envelope read through
    /// its opened key, or with no key row the plain file. `None` when this
    /// directory does not hold it, or the key is another scope's.
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
        let Some(row) = row else {
            return Ok(self
                .open_body(digest, len)?
                .map(|file| BodyFile::plain(file, len)));
        };
        let Some(sealed) = &self.sealed else {
            return Ok(None);
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

    /// The sparse line index of the body `digest`, `len` bytes long, as
    /// `row` names it: the sealed index of an envelope, or the plain one.
    /// `None` when there is none, or it does not read whole: it is derived.
    pub(crate) fn line_index_of(
        &self,
        digest: &[u8; 32],
        len: u64,
        row: Option<&BodyKeyRow>,
    ) -> Option<Vec<u64>> {
        let Some(row) = row else {
            return self.read_line_index(digest, len);
        };
        let key = row.open(digest, self.sealed.as_ref()?).ok()??;
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
