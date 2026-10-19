//! The custody anchor (KS-4, FIX 5685): one lineage's current position, kept
//! where neither the vault's image nor its custody rolls it back, read with
//! authentication and advanced only by compare-and-swap.
//!
//! A record is `"OCAN" | u8 1 | position (96) | tag (32)`: the position in
//! the clear, so a keyless store checks that an advance extends it, and a
//! BLAKE3 keyed tag under the lineage's anchor key, so a reader holding the
//! head's control secret knows the record is the lineage's own. A signed
//! record carried with a backup proves no freshness; only the store's
//! current one does.
//!
//! The self-host store ([`FileAnchor`]) is one directory the owner selects,
//! outside the vault and its custody: `<namespace hex>.<vault hex>.anchor`
//! per lineage, replaced atomically and synced under an exclusive lock on
//! `<namespace hex>.<vault hex>.lock`. Its root is never made here: a
//! missing one (an unmounted disk) is a pending anchor, never a directory
//! quietly made on the local disk.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::error::{Error, Result};

use super::files::read_whole;
use super::identity::{CustodyNamespace, CustodyVaultId};
use super::log::{Control, CustodyPosition, POSITION_LEN};
use super::platform;
use super::protocol::{AnchorAdvance, AnchorStore};

const ANCHOR_MAGIC: &[u8; 4] = b"OCAN";
const ANCHOR_VERSION: u8 = 1;
const RECORD_LEN: usize = 4 + 1 + POSITION_LEN + 32;

pub(super) fn anchor_corrupt() -> Error {
    Error::CorruptedIndex("key custody anchor")
}

/// The record anchoring `position`, tagged under `control`'s anchor key.
pub(super) fn anchor_record(position: &CustodyPosition, control: &Control) -> Vec<u8> {
    let mut out = ANCHOR_MAGIC.to_vec();
    out.push(ANCHOR_VERSION);
    out.extend_from_slice(&position.to_bytes());
    let tag = blake3::keyed_hash(&control.anchor_key(), &out);
    out.extend_from_slice(tag.as_bytes());
    out
}

/// The position a record claims, unauthenticated: what a keyless store
/// checks an advance against.
pub(crate) fn anchored_position(record: &[u8]) -> Result<CustodyPosition> {
    if record.len() != RECORD_LEN || &record[..4] != ANCHOR_MAGIC || record[4] != ANCHOR_VERSION {
        return Err(anchor_corrupt());
    }
    CustodyPosition::from_bytes(&record[5..5 + POSITION_LEN]).ok_or_else(anchor_corrupt)
}

/// The position a record anchors, once its tag checks under the lineage's
/// anchor key: refused for a record the lineage did not write.
pub(super) fn verified_position(record: &[u8], anchor_key: &[u8; 32]) -> Result<CustodyPosition> {
    let position = anchored_position(record)?;
    let (body, tag) = record.split_at(RECORD_LEN - 32);
    let tag: [u8; 32] = tag.try_into().map_err(|_| anchor_corrupt())?;
    // `Hash` compares in constant time.
    if blake3::keyed_hash(anchor_key, body) != blake3::Hash::from(tag) {
        return Err(anchor_corrupt());
    }
    Ok(position)
}

/// Whether `next` may replace `current`: the same lineage, a writer epoch no
/// older, and in the same epoch a sequence no older. A folder or residence
/// head switch keeps the same rule.
pub(super) fn extends(current: &CustodyPosition, next: &CustodyPosition) -> bool {
    current.same_lineage(next)
        && next.epoch >= current.epoch
        && next.seq >= current.seq
        && (next.seq > current.seq || next.epoch > current.epoch || next.tip == current.tip)
}

/// The self-host anchor: one owner-selected directory, outside the vault
/// and its custody.
pub(crate) struct FileAnchor {
    root: PathBuf,
}

impl FileAnchor {
    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    fn stem(vault: CustodyVaultId, namespace: CustodyNamespace) -> String {
        format!(
            "{}.{}",
            crate::entity_id::bytes_to_hex_lower(namespace.as_bytes()),
            crate::entity_id::bytes_to_hex_lower(vault.as_bytes())
        )
    }

    /// The root, refused while it is missing or not a directory.
    fn present_root(&self) -> Result<&Path> {
        match std::fs::metadata(&self.root) {
            Ok(meta) if meta.is_dir() => Ok(&self.root),
            Ok(_) => Err(Error::InvalidConfig(format!(
                "the custody anchor root {} is not a directory",
                self.root.display()
            ))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(Error::InvalidConfig(
                format!("the custody anchor root {} is missing", self.root.display()),
            )),
            Err(err) => Err(err.into()),
        }
    }

    /// Holds the lineage's lock for the life of the returned file, through
    /// the read, compare, temporary flush, replacement and directory sync.
    fn lock(&self, stem: &str) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        let lock =
            platform::secure(&mut options).open(self.present_root()?.join(format!("{stem}.lock")))?;
        platform::lock_exclusive(&lock)?;
        Ok(lock)
    }
}

impl AnchorStore for FileAnchor {
    fn read(&self, vault: CustodyVaultId, namespace: CustodyNamespace) -> Result<Option<Vec<u8>>> {
        let stem = Self::stem(vault, namespace);
        read_whole(&self.present_root()?.join(format!("{stem}.anchor")))
    }

    fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> Result<AnchorAdvance> {
        let next = anchored_position(record)?;
        let stem = Self::stem(next.vault, next.namespace);
        let _lock = self.lock(&stem)?;
        let root = self.present_root()?;
        let name = format!("{stem}.anchor");
        let current = read_whole(&root.join(&name))?;
        if current
            .as_deref()
            .map(|current| *blake3::hash(current).as_bytes())
            != expected
        {
            return Ok(AnchorAdvance::Moved);
        }
        if let Some(current) = &current
            && !extends(&anchored_position(current)?, &next)
        {
            return Err(Error::InvalidConfig(
                "a custody anchor advance must extend the anchored position".into(),
            ));
        }
        let temp = root.join(format!(".{stem}.{:016x}.tmp", rand::rngs::OsRng.next_u64()));
        let written = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = platform::secure(&mut options).open(&temp)?;
            file.write_all(record)?;
            file.sync_all()?;
            std::fs::rename(&temp, root.join(&name))?;
            platform::sync_dir(root)?;
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written.map(|()| AnchorAdvance::Advanced)
    }
}
