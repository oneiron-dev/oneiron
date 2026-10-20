//! The read-only door to a sealed vault (OF-570 maximum tier): the page key
//! a reader that opens no `Vault` gives LMDB, and LMDB's refusals in the
//! owner's words (moved out of `page_seal` whole).

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};

use zeroize::Zeroizing;

use super::{OPENED, VaultPageSeal, vault_is_sealed};
use crate::error::{Error, Result};
use crate::world_keys::refused;

/// LMDB refuses a sealed file opened without a key, or a plain one with one.
const MDB_ENV_ENCRYPTION: i32 = -30776;
/// LMDB refuses a page that does not open under the key.
const MDB_CRYPTO_FAIL: i32 = -30777;

thread_local! {
    /// The page key the read-only door opens one sealed vault with on this
    /// thread, by canonical root, for the length of one read ([`read_sealed`]).
    static READING: RefCell<Option<(PathBuf, Arc<Zeroizing<[u8; 32]>>)>> =
        const { RefCell::new(None) };
}

/// Puts the page key on `options` when the vault at `root` is sealed, for a
/// door that opens it without a config: the seal its reader passed
/// ([`read_sealed`]), or the key of a vault this process opened. A sealed
/// vault this process never opened, read with no seal, refuses.
pub(crate) fn seal_read_only(options: &mut heed::EnvOpenOptions, root: &Path) -> Result<bool> {
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let explicit = READING.with(|reading| {
        reading
            .borrow()
            .as_ref()
            .filter(|(path, _)| *path == canonical)
            .map(|(_, key)| Arc::clone(key))
    });
    let opened = explicit.or_else(|| {
        OPENED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&canonical)
            .cloned()
    });
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

/// Runs `read`, which reads the vault at `root` through the read-only door,
/// with `seal` as that vault's page seal: how a reader beside a sealed vault
/// another process serves passes its seal, explicitly, for each read. With
/// no seal, `read` runs as it is.
pub(crate) fn read_sealed<T>(
    root: &Path,
    seal: Option<&VaultPageSeal>,
    read: impl FnOnce() -> Result<T>,
) -> Result<T> {
    /// Puts back what the thread read with before, however `read` ends.
    struct Restore(Option<(PathBuf, Arc<Zeroizing<[u8; 32]>>)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            READING.with(|reading| *reading.borrow_mut() = previous);
        }
    }
    let Some(seal) = seal else {
        return read();
    };
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let _restore = Restore(
        READING.with(|reading| reading.replace(Some((canonical, Arc::clone(&seal.page_key))))),
    );
    read()
}

/// The error of an environment opened with (`keyed`) or without a page key,
/// in the owner's words where LMDB refused the seal.
pub(crate) fn page_seal_open_error(error: heed::Error, keyed: bool) -> Error {
    let code = match &error {
        heed::Error::Mdb(heed::MdbError::Other(code)) => Some(*code),
        // heed hands an LMDB code it has no name for over as a raw OS error.
        heed::Error::Io(error) => error.raw_os_error(),
        _ => None,
    };
    match code {
        Some(MDB_ENV_ENCRYPTION) if keyed => {
            refused("this vault is plain: the maximum tier is chosen when the vault is created")
        }
        Some(MDB_ENV_ENCRYPTION) => {
            refused("this vault is sealed (maximum tier): unlock it with its vault key")
        }
        Some(MDB_CRYPTO_FAIL) => refused("this vault's pages do not open with this page key"),
        _ => error.into(),
    }
}
