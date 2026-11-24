//! Windows: one file per slot in a directory of its own, each sealed by DPAPI to
//! this user on this machine (`CryptProtectData`, never a prompt), with the
//! slot's name as the extra entropy, so one slot's file never opens as another
//! slot (OF-168).
//!
//! The directory must lie outside every vault directory, because a vault's
//! checkpoints and backups copy what is inside it; the default one sits in the
//! profile's local part, which never roams. A copied file opens for no other
//! user and on no other machine. It does open for this user's own processes,
//! as every platform tier does.
//!
//! The same directory keeps the bytes the engine sealed under a device PIN
//! ([`SealedBytesStore`]): one file per name, `<name>.sealed`, sealed by DPAPI
//! as a slot is, with an entropy no slot has. So a sealed value's file opens
//! for no other user and on no other machine either, and neither it nor a
//! slot's file opens as the other.
//!
//! The directory follows the Unix file tier's rules ([`crate::key_dir`]): one
//! inside a vault directory is refused and leaves nothing behind, and each
//! file is written to a temporary file under a shared hold on
//! `temp-writers.lock`. A writer killed before its link or rename leaves that
//! file, which DPAPI opens for this user; the sweeps at open, at each create,
//! replace and put, and at each delete remove it once no writer holds the
//! directory. A replace, a put or a delete reports a copy it could not
//! remove.

use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

use crate::dpapi_names::{sealed_entropy, sealed_file_name, slot_entropy, slot_file_name};
use crate::key_dir::{self, TempFile};
use crate::sealed_bytes::check_sealed_len;
use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
    SEALED_BYTES_MAX, SealedBytesName, SealedBytesStore,
};

/// No sealed slot comes near this; a larger file is not one.
const SLOT_FILE_MAX: usize = 4096;

/// The largest file of one sealed value. DPAPI adds a few hundred bytes to
/// what it seals, so the file of a value at [`SEALED_BYTES_MAX`] stays far
/// below this. `put_sealed` writes no larger file, and a larger one is not
/// read.
const SEALED_FILE_MAX: usize = 2 * SEALED_BYTES_MAX;

const SLOT_NOT_OPENED: &str = "the slot does not open for this user on this machine";
const SEALED_NOT_OPENED: &str = "the sealed file does not open for this user on this machine";

/// One DPAPI-sealed file per slot under `dir`.
#[derive(Debug)]
pub struct WindowsDpapiKeystore {
    dir: PathBuf,
}

impl WindowsDpapiKeystore {
    /// Creates `dir` when absent. It refuses one inside any of `vault_dirs`,
    /// and the refusal leaves no directory it made behind.
    pub fn open(dir: &Path, vault_dirs: &[&Path]) -> Result<Self> {
        let dir = key_dir::create_key_dir(dir, vault_dirs, |dir| fs::create_dir(dir))?;
        if !fs::metadata(&dir).map_err(io)?.is_dir() {
            return Err(KeystoreError::Corrupt(
                "the key directory is not a directory",
            ));
        }
        // Every slot's and sealed value's stale temporary files, once; a file
        // it cannot remove waits for a later sweep.
        let _ = key_dir::sweep_temps(&dir, None);
        Ok(Self { dir })
    }

    fn path(&self, slot: &KeystoreSlot) -> PathBuf {
        self.dir.join(slot_file_name(slot))
    }

    /// The file of one sealed value, under a suffix no slot file has.
    fn sealed_path(&self, name: &SealedBytesName) -> PathBuf {
        self.dir.join(sealed_file_name(name))
    }

    /// Seals `bytes` with `entropy` and syncs one temporary file beside the
    /// file it will become, under the writer's hold on the key directory
    /// ([`key_dir::write_temp`]), removing it if any step fails. `stem` is
    /// that file's part of the temporary file's name. A sealed form longer
    /// than `sealed_max`, which the reader of that file would refuse, is
    /// refused here before any file is made. The caller keeps the answer
    /// until it has removed the temporary file.
    fn write_temp(
        &self,
        stem: &str,
        bytes: &[u8],
        entropy: &[u8],
        sealed_max: usize,
    ) -> Result<TempFile> {
        let sealed = protect(bytes, entropy)?;
        if sealed.len() > sealed_max {
            return Err(KeystoreError::Unsupported(
                "DPAPI's sealed form is longer than its file may be",
            ));
        }
        let (tmp, written) = key_dir::write_temp(&self.dir, stem, &sealed, |_| Ok(()));
        match written {
            Ok(()) => Ok(tmp),
            Err(error) => {
                let _ = fs::remove_file(&tmp.path);
                Err(io(error))
            }
        }
    }
}

impl DeviceKeystore for WindowsDpapiKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let file = match File::open(self.path(slot)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let mut sealed = Vec::with_capacity(SLOT_FILE_MAX + 1);
        file.take(SLOT_FILE_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.len() > SLOT_FILE_MAX {
            return Err(KeystoreError::Corrupt("the slot file is too large"));
        }
        let opened = unprotect(&sealed, &slot_entropy(slot), SLOT_NOT_OPENED)?;
        <[u8; 32]>::try_from(opened.as_slice())
            .map(|secret| Some(Zeroizing::new(secret)))
            .map_err(|_| KeystoreError::Corrupt("the slot is not 32 bytes"))
    }

    /// Writes a temporary file, then links it into place. A crash leaves either
    /// no slot or a whole one, and the link never replaces a filled slot.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        // FIX 8019: sweep this slot's stale temporary files before writing.
        // The slot is empty, so a file that stays holds no value of it; its
        // delete reports such a file.
        let _ = key_dir::sweep_temps(&self.dir, Some(&slot.name()));
        let path = self.path(slot);
        let tmp = self.write_temp(&slot.name(), secret, &slot_entropy(slot), SLOT_FILE_MAX)?;
        let linked = fs::hard_link(&tmp.path, &path);
        // A failed removal is swept by a later open, create or delete.
        let _ = fs::remove_file(&tmp.path);
        match linked {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(KeystoreError::AlreadyExists),
            Err(e) => Err(io(e)),
        }
    }

    /// Removes the slot's file, and then every stale temporary copy of it,
    /// also when the slot's file is gone already. A copy that stays (one a
    /// reader holds open without sharing its delete) is an error.
    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        match fs::remove_file(self.path(slot)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        key_dir::sweep_temps(&self.dir, Some(&slot.name())).map_err(io)
    }

    /// Writes a sealed temporary file, then renames it over the filled slot:
    /// one rename, so a reader opens the old slot or the new one, never none.
    /// A stale copy of the old slot goes first, and one that stays is an
    /// error before anything is written.
    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let path = self.path(slot);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Err(KeystoreError::Corrupt("the slot is not a file")),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io(e)),
        }
        key_dir::sweep_temps(&self.dir, Some(&slot.name())).map_err(io)?;
        let tmp = self.write_temp(&slot.name(), secret, &slot_entropy(slot), SLOT_FILE_MAX)?;
        let renamed = fs::rename(&tmp.path, &path);
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp.path);
        }
        renamed.map_err(io)?;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Platform
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(self)
    }
}

impl SealedBytesStore for WindowsDpapiKeystore {
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>> {
        let file = match File::open(self.sealed_path(name)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let mut sealed = Vec::new();
        file.take(SEALED_FILE_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.len() > SEALED_FILE_MAX {
            return Err(KeystoreError::Corrupt("the sealed file is too large"));
        }
        let opened = unprotect(&sealed, &sealed_entropy(name), SEALED_NOT_OPENED)?;
        if opened.is_empty() || opened.len() > SEALED_BYTES_MAX {
            return Err(KeystoreError::Corrupt(
                "the sealed file is empty or longer than a home keeps",
            ));
        }
        Ok(Some(opened.to_vec()))
    }

    /// Writes a sealed temporary file, then renames it into place: one
    /// rename, so a reader opens the old file or the new one, and a crash
    /// leaves one of the two whole.
    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<()> {
        check_sealed_len(sealed)?;
        // A stale copy of an earlier value under this name goes first, and
        // one that stays is an error before anything is written.
        key_dir::sweep_temps(&self.dir, Some(&sealed_file_name(name))).map_err(io)?;
        let tmp = self.write_temp(
            &sealed_file_name(name),
            sealed,
            &sealed_entropy(name),
            SEALED_FILE_MAX,
        )?;
        let renamed = fs::rename(&tmp.path, self.sealed_path(name));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp.path);
        }
        renamed.map_err(io)
    }

    /// Removes the value's file, and then every stale temporary copy of it,
    /// also when the value's file is gone already. A copy that stays is an
    /// error.
    fn delete_sealed(&self, name: &SealedBytesName) -> Result<()> {
        match fs::remove_file(self.sealed_path(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        key_dir::sweep_temps(&self.dir, Some(&sealed_file_name(name))).map_err(io)
    }
}

/// A DPAPI input over `bytes`, which DPAPI only reads.
fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())
            .map_err(|_| KeystoreError::Corrupt("the slot file is too large"))?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn empty() -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    }
}

/// DPAPI's output, copied out, then wiped and freed where DPAPI put it.
fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    if out.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    let len = usize::try_from(out.cbData).unwrap_or(0);
    // SAFETY: on success DPAPI hands back `cbData` bytes at `pbData`, allocated
    // with `LocalAlloc` and owned by the caller; they are read, wiped and freed
    // here once, and never touched after `LocalFree`.
    unsafe {
        let bytes = std::slice::from_raw_parts_mut(out.pbData, len);
        let copy = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        LocalFree(out.pbData.cast());
        copy
    }
}

fn protect(bytes: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = blob(bytes)?;
    let extra = blob(entropy)?;
    let mut out = empty();
    // SAFETY: both inputs point at live buffers for the call; no description,
    // reserved word or prompt is passed; `out` receives a buffer `take` frees.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &extra,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(last_error("CryptProtectData"));
    }
    Ok(take(out))
}

/// Opens what `protect` sealed with the same `entropy`, for this user on this
/// machine. Anything else is `not_opened`.
fn unprotect(
    sealed: &[u8],
    entropy: &[u8],
    not_opened: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let input = blob(sealed)?;
    let extra = blob(entropy)?;
    let mut out = empty();
    // SAFETY: as in `protect`; the description pointer is null, so none is
    // returned to free.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &extra,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(KeystoreError::Corrupt(not_opened));
    }
    Ok(take(out))
}

fn last_error(call: &'static str) -> KeystoreError {
    KeystoreError::Platform(
        call,
        std::io::Error::last_os_error()
            .raw_os_error()
            .map_or(-1, i64::from),
    )
}

fn io(e: std::io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}
