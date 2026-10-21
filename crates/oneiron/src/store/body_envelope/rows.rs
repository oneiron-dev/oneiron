//! A body instance's row (FIX 5348, KS-2A): one per digest, in
//! `PROVENANCE_BODY_KEY`, beside the body's descriptors. It names the
//! instance whose key typed custody holds, the format version and chunk
//! format, the body's logical length and whether the body rests in the row
//! naming it (an inline result) or a file. A vault's row holds no key and no
//! wrap of one, so no image that carries it recovers a key: only current
//! custody opens the instance ([`super::custody`]). An off-record session's
//! row alone carries its file key wrapped for the session's scope under the
//! vault's body-file wrap key, and stays in the session's overlay, in
//! memory. The body's logical BLAKE3 and length stay what its holders and
//! descriptors name.

use std::sync::Arc;

use getrandom::SysRng;
use heed::{RoTxn, RwTxn};
use oneiron_crypto::{
    Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId, WrapType,
    seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::custody::{body_key_in, pin_body_custody_in_txn};
use super::frames::{FORMAT_VERSION, FileKey};
use super::{BodyDir, BodySeal, DirSeal, KeyScope, StagedBodyKey};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable, SideTableDbs};
use crate::store::ManifestDbs;

/// The instance rows, by the body's BLAKE3.
pub(crate) const BODY_KEYS: SideTable<[u8; 32], BodyKeyRow, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_KEY);

/// Every instance a digest was bound under that its row no longer names, or
/// may stop naming: one an inline/file switch displaced, its successor, and
/// one the collector released (FIX 6023). Ids only.
pub(crate) const BODY_INSTANCES: SideTable<([u8; 32], [u8; 16]), Vec<u8>, Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_INSTANCE);

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

/// One body instance's row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyKeyRow {
    /// The instance's random id: a sealed file's name is
    /// `<digest>-<instance>`, and custody keys it.
    pub(crate) instance: [u8; 16],
    pub(crate) version: u16,
    /// The body's logical length.
    pub(crate) len: u64,
    pub(crate) format: BodyFileFormat,
    /// The body rests in the row naming it (an inline result), not a file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) inline: bool,
    /// An off-record session's file key, an E0 envelope under the vault's
    /// wrap key, for the session's scope: in its overlay only. A vault row
    /// holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped: Option<Vec<u8>>,
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
    /// The vault's row of `instance`, the body of `len` bytes: no key and no
    /// wrap, custody holds the key. `inline` when the body rests in the row
    /// naming it.
    pub(crate) fn vault(instance: [u8; 16], len: u64, inline: bool) -> Self {
        Self {
            instance,
            version: FORMAT_VERSION,
            len,
            format: FORMAT,
            inline,
            wrapped: None,
        }
    }

    /// An off-record session's row of `key`, the key of the body `digest`
    /// of `len` bytes, wrapped for the session's scope under `seal`.
    pub(super) fn off_record(
        seal_key: &BodySeal,
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
            recipient: KeyScope::OffRecord.recipient(),
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
            wrapped: Some(wrapped),
            ..Self::vault(*key.instance(), len, false)
        })
    }

    /// Whether this is a vault row, whose instance custody holds: an
    /// off-record row's never reaches the vault's history.
    pub(crate) fn is_vault(&self) -> bool {
        self.wrapped.is_none()
    }

    /// Whether this row is `scope`'s: a vault row wraps nothing, an
    /// off-record one its key for that scope, as its envelope says before it
    /// opens.
    pub(super) fn wrapped_for(&self, scope: KeyScope) -> Result<bool> {
        if self.version != FORMAT_VERSION || self.format != FORMAT {
            return Err(corrupt());
        }
        Ok(match (&self.wrapped, scope) {
            (None, KeyScope::Vault) => true,
            (Some(wrapped), KeyScope::OffRecord) => {
                Envelope::parse(wrapped)
                    .map_err(|_| corrupt())?
                    .header()
                    .recipient
                    == KeyScope::OffRecord.recipient()
            }
            _ => false,
        })
    }

    /// The off-record file key this row wraps, under `seal`.
    fn open_wrapped(&self, digest: &[u8; 32], seal_key: &BodySeal) -> Result<Arc<FileKey>> {
        let wrapped = self.wrapped.as_ref().ok_or_else(corrupt)?;
        let key_id = wrap_key_id(digest, &self.instance, self.len);
        let policy = OpenPolicy {
            purpose: Purpose::BodyFileKey,
            vault_id: &seal_key.vault_id,
            recipient: KeyScope::OffRecord.recipient(),
            key_id: &key_id,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[AEAD],
            kem_suites: &[],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let opened = Envelope::parse(wrapped)
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

    /// The file key of the body `digest` this row names, for the sealed
    /// directory `dir` seals: a vault row's from current custody, an
    /// off-record row's unwrapped. `None` when the row is another scope's.
    pub(super) fn open(&self, digest: &[u8; 32], dir: &DirSeal) -> Result<Option<Arc<FileKey>>> {
        if !self.wrapped_for(dir.scope)? {
            return Ok(None);
        }
        match dir.scope {
            KeyScope::Vault => {
                let custody = dir
                    .custody
                    .as_ref()
                    .ok_or_else(|| super::custody::custody_unavailable(1))?;
                body_key_in(custody, &self.instance).map(Some)
            }
            KeyScope::OffRecord => self.open_wrapped(digest, dir.seal()?).map(Some),
        }
    }
}

/// The instance row of the body `digest` in `txn`'s snapshot of `dbs`: a
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

/// Commits `staged`'s instance row in the transaction that writes the row
/// or descriptor naming its body, its file published in `dir`, and pins the
/// custody binding with it. A digest that already has a committed pair there
/// keeps it: the staged file is then an orphan the collector takes, its
/// instance unnamed debris, and no committed file's instance is replaced. A
/// row whose file is gone is no pair, and the staged one takes its place.
///
/// # Errors
///
/// Storage and filesystem errors, and a row that does not parse.
pub(crate) fn bind_body_key_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    txn: &mut RwTxn<'_>,
    dir: &BodyDir,
    staged: &StagedBodyKey,
) -> Result<()> {
    let held = BODY_KEYS.get(dbs, txn, &staged.digest)?;
    if let Some(held) = &held
        && staged.keeps(held, dir)?
    {
        return Ok(());
    }
    pin_body_custody_in_txn(dbs, txn)?;
    if let Some(held) = held
        && held.is_vault()
        && staged.row.is_vault()
    {
        // The instance it replaces stays the digest's (FIX 6023).
        remember_body_instances_in_txn(
            dbs,
            txn,
            &staged.digest,
            &[held.instance, staged.row.instance],
        )?;
    }
    BODY_KEYS.put(dbs, txn, &staged.digest, &staged.row)
}

/// Remembers each of `instances` as one the body `digest` was bound under,
/// in `wtxn`, journaling the rows it adds in custody before the writer
/// commits (FIX 6023, 6229): a last-holder erase of the digest retires each,
/// so no copy an older image carries under a displaced or released instance
/// outlives it. A delete and the collector keep them; an aborted writer
/// leaves the journal a row more, never one less.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn remember_body_instances_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    digest: &[u8; 32],
    instances: &[[u8; 16]],
) -> Result<()> {
    let mut journaled = Vec::new();
    for instance in instances {
        let key = (*digest, *instance);
        if !BODY_INSTANCES.contains(dbs, wtxn, &key)? {
            BODY_INSTANCES.put(dbs, wtxn, &key, &Vec::new())?;
            journaled.push((BODY_INSTANCES.key_bytes(&key), Vec::new()));
        }
    }
    dbs.key_custody().journal_body_history(journaled)
}

/// Every instance [`remember_body_instances_in_txn`] holds for the body
/// `digest`, in id order.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn remembered_body_instances_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Vec<[u8; 16]>> {
    Ok(BODY_INSTANCES
        .scan_keys(dbs, txn, digest)?
        .into_iter()
        .map(|(_, instance)| instance)
        .collect())
}

/// Deletes the instance row of the body `digest`, in the collector or erase
/// transaction that releases its final holder: the instance it named, so
/// its file goes after the commit; `None` for a body with no row.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn retire_body_key_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    txn: &mut RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<[u8; 16]>> {
    let Some(row) = BODY_KEYS.get(dbs, txn, digest)? else {
        return Ok(None);
    };
    BODY_KEYS.delete(dbs, txn, digest)?;
    // The released instance stays the digest's, so a later body of the same
    // bytes and its erase reach the copies older images keep (FIX 6023).
    if row.is_vault() {
        remember_body_instances_in_txn(dbs, txn, digest, &[row.instance])?;
    }
    Ok(Some(row.instance))
}
