//! The maximum tier (OF-570): every LMDB page of a vault sealed under a page
//! key. It is opt-in, chosen when the vault is created, and slower
//! ([`PAGE_SEAL_WARNING`]).
//!
//! - The page key is `BLAKE3-derive_key("oneiron/vault-page-key/v1",
//!   incarnation ‖ vault data key)`. The incarnation is 32 random bytes per
//!   created environment.
//! - LMDB needs the page key before the vault opens, so the vault key's
//!   commitment and wraps also rest in a mirror beside the vault,
//!   `.<vault dir name>.page-seal`, owner-only. Like the gate decision keys it
//!   is never inside the vault and never in a checkpoint image. It holds only
//!   sealed envelopes and public facts, as a sealed artifact does.
//! - The mirror is rewritten from the vault after each wrap change and on each
//!   sealed open, once the vault has a wrap.
//!
//! Body files, `.lines`, LFS staging and lock files stay outside the tier.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::vault_key::{CarriedVaultKey, VaultDataKey, VaultKeyUnlock};
use super::{os_fill, refused};
use crate::Vault;
use crate::error::{Error, Result};

/// What the owner is told before choosing the tier, and while it is on.
pub const PAGE_SEAL_WARNING: &str =
    "the maximum tier seals every vault page and is slower: point reads about 20x, scans about 12x";

const PAGE_KEY_CONTEXT: &str = "oneiron/vault-page-key/v1";
const MIRROR_VERSION: u32 = 1;
/// The most of a mirror file that is read.
const MIRROR_LIMIT: u64 = 1 << 20;
/// LMDB refuses a sealed file opened without a key, or a plain one with one.
const MDB_ENV_ENCRYPTION: i32 = -30776;
/// LMDB refuses a page that does not open under the key.
const MDB_CRYPTO_FAIL: i32 = -30777;

/// The page keys of the sealed vaults this process opened, by canonical root:
/// what a read-only door opens one with.
static OPENED: LazyLock<Mutex<HashMap<PathBuf, Arc<Zeroizing<[u8; 32]>>>>> =
    LazyLock::new(Default::default);
/// Held while a mirror is read from a vault and written, so the last writer
/// writes the latest wraps.
static MIRRORING: Mutex<()> = Mutex::new(());

/// What opens a sealed vault's pages: the page key, the vault it belongs to,
/// and the vault data key it derives from. No `Serialize`, a `Debug` that
/// prints nothing, and the keys are wiped when the last clone drops.
#[derive(Clone)]
pub struct VaultPageSeal {
    vault_id: [u8; 32],
    incarnation: [u8; 32],
    page_key: Arc<Zeroizing<[u8; 32]>>,
    data_key: Arc<VaultDataKey>,
}

impl std::fmt::Debug for VaultPageSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultPageSeal(..)")
    }
}

impl PartialEq for VaultPageSeal {
    fn eq(&self, other: &Self) -> bool {
        let diff = self
            .page_key
            .iter()
            .zip(other.page_key.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        self.vault_id == other.vault_id && self.incarnation == other.incarnation && diff == 0
    }
}

impl VaultPageSeal {
    fn derive(vault_id: [u8; 32], incarnation: [u8; 32], data_key: VaultDataKey) -> Self {
        let page_key = Arc::new(Zeroizing::new(data_key.derive(PAGE_KEY_CONTEXT, &incarnation)));
        Self {
            vault_id,
            incarnation,
            page_key,
            data_key: Arc::new(data_key),
        }
    }

    /// The vault this seal belongs to. A new vault takes it as its own id.
    #[must_use]
    pub fn vault_id(&self) -> [u8; 32] {
        self.vault_id
    }

    /// The page key, for the environment builders.
    pub(crate) fn page_key(&self) -> &[u8; 32] {
        &self.page_key
    }
}

/// The mirror file's content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mirror {
    version: u32,
    vault_id: [u8; 32],
    incarnation: [u8; 32],
    carried: CarriedVaultKey,
}

/// Where the vault at `vault_path` keeps its page-seal mirror:
/// `<parent>/.<vault dir name>.page-seal`, beside the vault, never in it.
pub fn page_seal_custody_path(vault_path: &Path) -> Result<PathBuf> {
    let root = match vault_path.canonicalize() {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::path::absolute(vault_path)?
        }
        Err(error) => return Err(error.into()),
    };
    mirror_beside(&root)
}

fn mirror_beside(root: &Path) -> Result<PathBuf> {
    let name = root
        .file_name()
        .ok_or_else(|| refused("a vault path names a directory"))?;
    let mut file = std::ffi::OsString::from(".");
    file.push(name);
    file.push(".page-seal");
    Ok(root.with_file_name(file))
}

/// Whether the vault at `vault_path` is sealed: its mirror is there.
pub fn vault_is_sealed(vault_path: &Path) -> Result<bool> {
    match fs::symlink_metadata(page_seal_custody_path(vault_path)?) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// A seal for a new vault at `vault_path`: a fresh vault id, data key and
/// incarnation. Refused where a vault or a mirror already is. It writes
/// nothing: the open takes it, and the mirror follows the first wrap.
pub fn new_page_seal(vault_path: &Path) -> Result<VaultPageSeal> {
    if vault_is_sealed(vault_path)? {
        return Err(refused("a page-seal mirror is already beside this vault"));
    }
    if fs::symlink_metadata(vault_path.join("data.mdb")).is_ok() {
        return Err(refused("the maximum tier is chosen when the vault is created"));
    }
    let mut vault_id = [0u8; 32];
    let mut incarnation = [0u8; 32];
    os_fill(&mut vault_id)?;
    os_fill(&mut incarnation)?;
    Ok(VaultPageSeal::derive(vault_id, incarnation, VaultDataKey::generate()?))
}

/// Unlocks the pages of the sealed vault at `vault_path` from its mirror,
/// with any of its vault key's wraps.
pub fn unlock_page_seal(vault_path: &Path, unlock: &VaultKeyUnlock<'_>) -> Result<VaultPageSeal> {
    let mirror = read_mirror(vault_path)?;
    let key = mirror.carried.open(&mirror.vault_id, unlock)?;
    Ok(VaultPageSeal::derive(mirror.vault_id, mirror.incarnation, key))
}

/// The vault id the mirror of the sealed vault at `vault_path` names: a
/// public fact, read with no secret.
pub fn page_seal_vault_id(vault_path: &Path) -> Result<[u8; 32]> {
    Ok(read_mirror(vault_path)?.vault_id)
}

fn read_mirror(vault_path: &Path) -> Result<Mirror> {
    let path = page_seal_custody_path(vault_path)?;
    let file = open_no_follow(&path, false)?;
    if !file.metadata()?.is_file() {
        return Err(refused("the page-seal mirror is not a file"));
    }
    let mut raw = Vec::new();
    file.take(MIRROR_LIMIT + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MIRROR_LIMIT {
        return Err(refused("the page-seal mirror is too large"));
    }
    let mirror: Mirror =
        serde_json::from_slice(&raw).map_err(|_| refused("the page-seal mirror is malformed"))?;
    if mirror.version != MIRROR_VERSION {
        return Err(refused("the page-seal mirror is of another version"));
    }
    Ok(mirror)
}

/// Writes the mirror beside `root`: a new temporary file, synced, renamed
/// over the mirror, then the directory synced.
fn write_mirror(root: &Path, mirror: &Mirror) -> Result<()> {
    let path = mirror_beside(root)?;
    let dir = path
        .parent()
        .ok_or_else(|| refused("a vault path names a directory"))?;
    #[cfg(not(unix))]
    let _ = dir;
    let raw =
        serde_json::to_vec(mirror).map_err(|_| refused("the page-seal mirror did not encode"))?;
    let mut suffix = [0u8; 8];
    os_fill(&mut suffix)?;
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(
        ".{}.tmp",
        crate::entity_id::bytes_to_hex_lower(&suffix)
    ));
    let temp = PathBuf::from(temp);
    let written = (|| -> Result<()> {
        let mut file = open_no_follow(&temp, true)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

/// Opens `path` without following a link: to read, or as a new owner-only
/// file to write.
fn open_no_follow(path: &Path, write_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if write_new {
        options.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// Puts the page key on `options` when the vault at `root` is sealed, for a
/// door that opens it without a config: the key of a vault this process
/// opened. A sealed vault this process never opened refuses.
pub(crate) fn seal_read_only(options: &mut heed::EnvOpenOptions, root: &Path) -> Result<bool> {
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let opened = OPENED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&canonical)
        .cloned();
    if let Some(key) = opened {
        options.page_key(&key);
        return Ok(true);
    }
    if vault_is_sealed(&canonical)? {
        return Err(refused(
            "this vault is sealed (maximum tier), and this process has not unlocked it",
        ));
    }
    Ok(false)
}

/// The error of an environment opened with (`keyed`) or without a page key,
/// in the owner's words where LMDB refused the seal.
pub(crate) fn page_seal_open_error(error: heed::Error, keyed: bool) -> Error {
    let code = match &error {
        heed::Error::Mdb(heed::MdbError::Other(code)) => Some(*code),
        _ => None,
    };
    match code {
        Some(MDB_ENV_ENCRYPTION) if keyed => refused(
            "this vault is plain: the maximum tier is chosen when the vault is created",
        ),
        Some(MDB_ENV_ENCRYPTION) => {
            refused("this vault is sealed (maximum tier): unlock it with its vault key")
        }
        Some(MDB_CRYPTO_FAIL) => refused("this vault's pages do not open with this page key"),
        _ => error.into(),
    }
}

impl Vault {
    /// Whether this vault's pages are sealed (the maximum tier).
    #[must_use]
    pub fn vault_pages_sealed(&self) -> bool {
        heed::Env::is_sealed(&self.store.env)
    }

    /// Settles the seal this vault opened with, before any caller holds it:
    /// the seal must be this vault's, a new vault takes its data key, the key
    /// is held, read-only doors in this process may open the vault, and the
    /// mirror is rewritten once the vault has a wrap.
    pub(crate) fn settle_page_seal(&self) -> Result<()> {
        let Some(seal) = self.config.page_seal.as_ref() else {
            return Ok(());
        };
        if *self.vault_id().as_bytes() != seal.vault_id {
            return Err(refused("the page seal belongs to another vault"));
        }
        self.admit_page_seal_key(&seal.data_key)?;
        OPENED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                self.store.env.path().to_path_buf(),
                Arc::clone(&seal.page_key),
            );
        self.sync_page_custody()
    }

    /// Rewrites the page-seal mirror from the vault's key state, when its
    /// pages are sealed and it has a wrap.
    pub(crate) fn sync_page_custody(&self) -> Result<()> {
        if !self.vault_pages_sealed() {
            return Ok(());
        }
        let seal = self
            .config
            .page_seal
            .as_ref()
            .ok_or_else(|| refused("a sealed vault is open without its page seal"))?;
        let _mirroring = MIRRORING.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(carried) = self.resting_vault_key()? else {
            return Ok(());
        };
        write_mirror(
            self.store.env.path(),
            &Mirror {
                version: MIRROR_VERSION,
                vault_id: seal.vault_id,
                incarnation: seal.incarnation,
                carried,
            },
        )
    }
}
