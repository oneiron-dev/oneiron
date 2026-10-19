//! A sealed body file's key row (FIX 5348): one per digest, in
//! `PROVENANCE_BODY_KEY`, beside the body's descriptors. It holds the file's
//! instance, the format version and chunk format, the body's logical length
//! and the file's data key wrapped under the vault's body-file wrap key. The
//! wrap binds the digest, the instance, the length and the format, and the
//! scope that may open it; the row holds no key in the clear and no
//! fingerprint of one. The body's logical BLAKE3 and length stay what its
//! holders and descriptors name.

use std::sync::Arc;

use getrandom::SysRng;
use heed::{RoTxn, RwTxn};
use oneiron_crypto::{
    Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId, WrapType,
    seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::frames::{FORMAT_VERSION, FileKey};
use super::{BodyDir, BodySeal, DirSeal, KeyScope, StagedBodyKey};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// The key rows, by the body's BLAKE3.
pub(crate) const BODY_KEYS: SideTable<[u8; 32], BodyKeyRow, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_KEY);

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const EPOCH: u64 = 1;

/// How a sealed body file is cut into envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BodyFileFormat {
    /// E0 chunks of 64 KiB of the body each, then a terminal record.
    #[serde(rename = "e0_chunks_64k")]
    E0Chunks64k,
}

impl BodyFileFormat {
    const fn code(self) -> u8 {
        match self {
            Self::E0Chunks64k => 1,
        }
    }
}

const FORMAT: BodyFileFormat = BodyFileFormat::E0Chunks64k;

/// One sealed body file's key row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyKeyRow {
    /// The file's own random id: its name is `<digest>-<instance>`.
    pub(crate) instance: [u8; 16],
    pub(crate) version: u16,
    /// The body's logical length.
    pub(crate) len: u64,
    pub(crate) format: BodyFileFormat,
    /// The file's data key, an E0 envelope under the wrap key.
    wrapped: Vec<u8>,
}

impl std::fmt::Debug for BodyKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyKeyRow")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("body file key row")
}

/// Digest ‖ instance ‖ u64be length ‖ u16be version ‖ format: a wrap's key
/// id.
fn wrap_key_id(digest: &[u8; 32], instance: &[u8; 16], len: u64) -> [u8; 59] {
    let mut out = [0u8; 59];
    out[..32].copy_from_slice(digest);
    out[32..48].copy_from_slice(instance);
    out[48..56].copy_from_slice(&len.to_be_bytes());
    out[56..58].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    out[58] = FORMAT.code();
    out
}

impl BodyKeyRow {
    /// The row of `key`, the key of the body `digest` of `len` bytes,
    /// wrapped for `scope` under `seal`.
    pub(super) fn wrap(
        seal_key: &BodySeal,
        scope: KeyScope,
        key: &FileKey,
        digest: &[u8; 32],
        len: u64,
    ) -> Result<Self> {
        let key_id = wrap_key_id(digest, key.instance(), len);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::BodyFileKey,
            epoch: EPOCH,
            key_id: &key_id,
            recipient: scope.recipient(),
            vault_id: &seal_key.vault_id,
        };
        let wrapped = seal(
            &params,
            SealKey::SymmetricKek(&seal_key.wrap),
            key.raw(),
            &mut SysRng,
        )
        .map_err(|_| crate::world_keys::refused("wrapping a body file's key failed"))?
        .to_bytes();
        Ok(Self {
            instance: *key.instance(),
            version: FORMAT_VERSION,
            len,
            format: FORMAT,
            wrapped,
        })
    }

    /// Whether this row's key is wrapped for `scope`, as its envelope says
    /// before it opens.
    pub(super) fn wrapped_for(&self, scope: KeyScope) -> Result<bool> {
        if self.version != FORMAT_VERSION || self.format != FORMAT {
            return Err(corrupt());
        }
        let envelope = Envelope::parse(&self.wrapped).map_err(|_| corrupt())?;
        Ok(envelope.header().recipient == scope.recipient())
    }

    /// The file key of the body `digest` this row wraps for `scope` under
    /// `seal`.
    pub(crate) fn open_under(
        &self,
        digest: &[u8; 32],
        seal_key: &BodySeal,
        scope: KeyScope,
    ) -> Result<Arc<FileKey>> {
        let key_id = wrap_key_id(digest, &self.instance, self.len);
        let policy = OpenPolicy {
            purpose: Purpose::BodyFileKey,
            vault_id: &seal_key.vault_id,
            recipient: scope.recipient(),
            key_id: &key_id,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[AEAD],
            kem_suites: &[],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let opened = Envelope::parse(&self.wrapped)
            .map_err(|_| corrupt())?
            .open(OpenKey::SymmetricKek(&seal_key.wrap), &policy)
            .map_err(|_| {
                crate::world_keys::refused("a body file's key does not open with this vault's key")
            })?;
        if opened.len() != 32 {
            return Err(corrupt());
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        raw.copy_from_slice(&opened);
        Ok(Arc::new(FileKey::from_raw(
            seal_key.vault_id,
            self.instance,
            raw,
        )))
    }

    /// The file key this row wraps, opened for the directory `dir` seals:
    /// `None` when it is wrapped for another scope.
    pub(super) fn open(&self, digest: &[u8; 32], dir: &DirSeal) -> Result<Option<Arc<FileKey>>> {
        if !self.wrapped_for(dir.scope)? {
            return Ok(None);
        }
        self.open_under(digest, dir.seal()?, dir.scope).map(Some)
    }

    /// This row, wrapped for `from`'s scope, wrapped again for `to`'s: the
    /// same file and key. `None` when it is not wrapped for `from`.
    pub(crate) fn rewrap(
        &self,
        digest: &[u8; 32],
        from: &DirSeal,
        to: &DirSeal,
    ) -> Result<Option<Self>> {
        let Some(key) = self.open(digest, from)? else {
            return Ok(None);
        };
        Self::wrap(to.seal()?, to.scope, &key, digest, self.len).map(Some)
    }
}

/// The key row of the body `digest` in `txn`'s snapshot of `dbs`: a
/// session's composed view reads its overlay's over the vault's.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn body_key_row_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<BodyKeyRow>> {
    BODY_KEYS.get(dbs, txn, digest)
}

/// Commits `staged`'s key row in the transaction that writes the row or
/// descriptor naming its body, its file published in `dir`. A digest that
/// already has a committed pair there keeps it: the staged file is then an
/// orphan the collector takes, and no committed file's key is replaced. A
/// key row whose file is gone is no pair, and the staged one takes its place.
///
/// # Errors
///
/// Storage and filesystem errors, and a row that does not parse.
pub(crate) fn bind_body_key_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    dir: &BodyDir,
    staged: &StagedBodyKey,
) -> Result<()> {
    if let Some(held) = BODY_KEYS.get(dbs, txn, &staged.digest)?
        && staged.keeps(&held, dir)?
    {
        return Ok(());
    }
    BODY_KEYS.put(dbs, txn, &staged.digest, &staged.row)
}

/// Deletes the key row of the body `digest`, in the collector transaction
/// that releases its final holder. The instance of the file it named, so
/// the file goes after the commit; `None` for a body with no key row.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn retire_body_key_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<[u8; 16]>> {
    let Some(row) = BODY_KEYS.get(dbs, txn, digest)? else {
        return Ok(None);
    };
    BODY_KEYS.delete(dbs, txn, digest)?;
    Ok(Some(row.instance))
}
