//! The creation record of a sealed vault (OF-570 maximum tier; FIX 1942,
//! 2546). A sealed vault's creation is unfinished from the moment its
//! environment is created until its first wrap is durable and its mirror is
//! written, or, under a delivered key, until its mirror is written. Nothing
//! is served in that window, so a vault left in it holds only what its
//! creation wrote, and it opens nothing.
//!
//! - Before the create door makes the environment, a record beside the
//!   mirror, `.<vault dir name>.page-seal-creation`, owner-only, names the
//!   vault path, the vault id and the incarnation: public facts, as the
//!   mirror's are, and nothing secret. Only a seal minted for a vault where
//!   none was records its creation; a fresh incarnation for a restore beside
//!   or over an open vault does not.
//! - The first mirror written with a committed wrap, or with a delivered
//!   key's commitment, ends the creation and removes the record; so does a
//!   passed [`Vault::check_page_custody`].
//! - A creation whose wrap failed in this process is removed at once
//!   ([`Vault::remove_unfinished_sealed_creation`]); one a crash left is
//!   removed at the next init or managed start
//!   ([`remove_unfinished_sealed_creation`]) and refused by every other door
//!   ([`refuse_unfinished_sealed_creation`]). The caller then creates the
//!   vault again as a first creation.
//! - A record that names another vault path is left alone.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use super::{
    OPENED, SealOrigin, VaultPageSeal, custody_root, has_data, mirror_beside, open_no_follow,
    read_mirror, write_owner_only,
};
use crate::Vault;
use crate::error::{Error, Result, SecretError};
use crate::store::VaultWriterLease;
use crate::world_keys::refused;

const RECORD_VERSION: u32 = 1;

/// The creation record's content: public facts only.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationRecord {
    version: u32,
    /// The canonical vault path, in the platform's encoding.
    vault_path: Vec<u8>,
    vault_id: [u8; 32],
    incarnation: [u8; 32],
}

impl CreationRecord {
    fn of(root: &Path, seal: &VaultPageSeal) -> Self {
        Self {
            version: RECORD_VERSION,
            vault_path: root.as_os_str().as_encoded_bytes().to_vec(),
            vault_id: seal.vault_id,
            incarnation: seal.incarnation,
        }
    }

    /// Whether this record names the vault path `root`.
    fn names_path(&self, root: &Path) -> bool {
        self.vault_path == root.as_os_str().as_encoded_bytes()
    }

    /// Whether this record names the vault at `root` under this vault id and
    /// incarnation.
    fn names(&self, root: &Path, vault_id: [u8; 32], incarnation: [u8; 32]) -> bool {
        self.names_path(root) && self.vault_id == vault_id && self.incarnation == incarnation
    }
}

/// Whether `seal` records the creation it makes: one minted for a vault
/// where none was, under a new or a delivered data key.
fn records_creation(seal: &VaultPageSeal) -> bool {
    matches!(
        seal.origin,
        SealOrigin::New | SealOrigin::Delivered { new: true }
    )
}

/// Where the creation record of the vault at `root` rests, beside its
/// mirror: `<parent>/.<vault dir name>.page-seal-creation`.
fn record_beside(root: &Path) -> Result<PathBuf> {
    let mut path = mirror_beside(root)?.into_os_string();
    path.push("-creation");
    Ok(PathBuf::from(path))
}

/// The creation record beside `root`, if there is one.
fn read_record(root: &Path) -> Result<Option<CreationRecord>> {
    let mut file = match open_no_follow(&record_beside(root)?, false) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(refused("the page-seal creation record is not a file"));
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    let record: CreationRecord = serde_json::from_slice(&raw)
        .map_err(|_| refused("the page-seal creation record is malformed"))?;
    if record.version != RECORD_VERSION {
        return Err(refused(
            "the page-seal creation record is of another version",
        ));
    }
    Ok(Some(record))
}

/// Removes the file at `path` when it is there, then syncs its directory.
fn remove_synced(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Records the creation of the vault at `root`, as the create door asks
/// before it makes any file there: under a seal that records its creation,
/// the record is written as the mirror is. Under any other, a record naming
/// `root` is stale, since the door found no environment there, and goes.
pub(super) fn begin_creation(root: &Path, seal: Option<&VaultPageSeal>) -> Result<()> {
    if let Some(seal) = seal.filter(|seal| records_creation(seal)) {
        let raw = serde_json::to_vec(&CreationRecord::of(root, seal))
            .map_err(|_| refused("the page-seal creation record did not encode"))?;
        return write_owner_only(&record_beside(root)?, &raw);
    }
    match read_record(root)? {
        Some(record) if record.names_path(root) => remove_synced(&record_beside(root)?),
        _ => Ok(()),
    }
}

/// Ends the creation of the vault at `root` under `seal`, once its first
/// wrap is durable and its mirror is written: the record naming that
/// creation goes. A seal that records no creation, and a record that names
/// another, leave everything as it is.
pub(super) fn finish_creation(root: &Path, seal: &VaultPageSeal) -> Result<()> {
    if !records_creation(seal) {
        return Ok(());
    }
    match read_record(root)? {
        Some(record) if record.names(root, seal.vault_id, seal.incarnation) => {
            remove_synced(&record_beside(root)?)
        }
        _ => Ok(()),
    }
}

/// Removes the unfinished creation of the sealed vault at `vault_path`, as
/// init and a managed start do before they open it (FIX 1942, 2546). A
/// creation record beside it that names that path says its creation never
/// finished and nothing was served from it: the mirror that creation wrote,
/// the vault's LMDB data and lock files, then the record go, and the caller
/// creates the vault again as a first creation. A record that names another
/// path is left alone. Whether a creation was removed.
pub fn remove_unfinished_sealed_creation(vault_path: &Path) -> Result<bool> {
    let root = custody_root(vault_path)?;
    match read_record(&root)? {
        Some(record) if record.names_path(&root) => {
            remove_creation(&root, &record)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Refuses the vault at `vault_path` while a creation record beside it names
/// that path and its environment is there (FIX 1942): that creation never
/// finished, so the vault opens nothing, and only init removes it and
/// creates it again. Nothing is removed here.
pub fn refuse_unfinished_sealed_creation(vault_path: &Path) -> Result<()> {
    let root = custody_root(vault_path)?;
    let unfinished = read_record(&root)?.is_some_and(|record| record.names_path(&root))
        && (has_data(&root) || fs::symlink_metadata(root.join("lock.mdb")).is_ok());
    if unfinished {
        return Err(Error::Secret(SecretError::UnfinishedSealedCreation));
    }
    Ok(())
}

/// Removes the creation record beside the vault at `vault_path` when it
/// names that path (FIX 11950): what a refused restore's destination guard
/// calls after it removes the copy and its mirror, so the record the copy's
/// failed first open left does not stay until the next init. Best effort, as
/// the guard's mirror removal is: a failure is logged and never panics or
/// returns an error. A record that names another path is left alone.
pub(crate) fn discard_creation_record(vault_path: &Path) {
    let removed = (|| -> Result<()> {
        let root = custody_root(vault_path)?;
        match read_record(&root)? {
            Some(record) if record.names_path(&root) => remove_synced(&record_beside(&root)?),
            _ => Ok(()),
        }
    })();
    if let Err(error) = removed {
        tracing::warn!(
            vault = %vault_path.display(),
            error = %error,
            "a refused restore left the page-seal creation record it wrote in place"
        );
    }
}

/// Removes what the creation `record` names made of the vault at `root`,
/// under that vault's writer lease, so no process that holds the vault loses
/// its files: the mirror the creation wrote, the LMDB data and lock files (a
/// torn creation's cleanup removes the same two), then the record, each
/// removal synced. A mirror of another vault or incarnation is refused and
/// kept.
fn remove_creation(root: &Path, record: &CreationRecord) -> Result<()> {
    let _lease = match VaultWriterLease::acquire(root) {
        Ok(lease) => Some(lease),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    match read_mirror(root) {
        Ok(mirror)
            if mirror.vault_id == record.vault_id
                && mirror.incarnations.contains(&record.incarnation) =>
        {
            remove_synced(&mirror_beside(root)?)?;
        }
        Ok(_) => {
            return Err(refused(
                "the page-seal mirror beside this unfinished vault creation is another vault's: \
                 move it away",
            ));
        }
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for name in ["data.mdb", "lock.mdb"] {
        remove_synced(&root.join(name))?;
    }
    remove_synced(&record_beside(root)?)?;
    OPENED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(root);
    tracing::warn!(
        vault = %root.display(),
        "a sealed vault's creation never finished; it was removed, to be created again"
    );
    Ok(())
}

impl Vault {
    /// Closes this vault and, while its creation is unfinished (the record
    /// beside it still names this vault and incarnation), removes what that
    /// creation made, as [`remove_unfinished_sealed_creation`] does at a
    /// start, so init simply runs again (FIX 1942): what a host calls when a
    /// new sealed vault's first wrap or mirror step failed. A vault whose
    /// creation finished, and a plain one, are only closed. Whether a
    /// creation was removed.
    pub fn remove_unfinished_sealed_creation(self) -> Result<bool> {
        let creation = self
            .config
            .page_seal
            .as_ref()
            .filter(|seal| records_creation(seal))
            .map(|seal| (seal.vault_id, seal.incarnation));
        let root = self.store.env.path().to_path_buf();
        drop(self);
        let Some((vault_id, incarnation)) = creation else {
            return Ok(false);
        };
        match read_record(&root)? {
            Some(record) if record.names(&root, vault_id, incarnation) => {
                remove_creation(&root, &record)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
