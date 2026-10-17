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

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
};

/// No sealed slot comes near this; a larger file is not one.
const SEALED_MAX: usize = 4096;

/// One DPAPI-sealed file per slot under `dir`.
#[derive(Debug)]
pub struct WindowsDpapiKeystore {
    dir: PathBuf,
}

impl WindowsDpapiKeystore {
    /// Creates `dir` when absent. It refuses one inside any of `vault_dirs`.
    pub fn open(dir: &Path, vault_dirs: &[&Path]) -> Result<Self> {
        fs::create_dir_all(dir).map_err(io)?;
        let dir = dir.canonicalize().map_err(io)?;
        for vault in vault_dirs {
            if let Ok(vault) = vault.canonicalize()
                && dir.starts_with(&vault)
            {
                return Err(KeystoreError::Unavailable(
                    "the key directory is inside a vault directory",
                ));
            }
        }
        if !fs::metadata(&dir).map_err(io)?.is_dir() {
            return Err(KeystoreError::Corrupt(
                "the key directory is not a directory",
            ));
        }
        Ok(Self { dir })
    }

    fn path(&self, slot: &KeystoreSlot) -> PathBuf {
        self.dir.join(format!("{}.dpapi", slot.name()))
    }
}

impl DeviceKeystore for WindowsDpapiKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let file = match File::open(self.path(slot)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let mut sealed = Vec::with_capacity(SEALED_MAX + 1);
        file.take(SEALED_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.len() > SEALED_MAX {
            return Err(KeystoreError::Corrupt("the slot file is too large"));
        }
        let opened = unprotect(&sealed, slot.name().as_bytes())?;
        <[u8; 32]>::try_from(opened.as_slice())
            .map(|secret| Some(Zeroizing::new(secret)))
            .map_err(|_| KeystoreError::Corrupt("the slot is not 32 bytes"))
    }

    /// Writes a temporary file, then links it into place. A crash leaves either
    /// no slot or a whole one, and the link never replaces a filled slot.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        let sealed = protect(secret, slot.name().as_bytes())?;
        let path = self.path(slot);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = self.dir.join(format!(
            ".{}.{}.{nanos}.tmp",
            slot.name(),
            std::process::id()
        ));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(&sealed)?;
                file.sync_all()
            });
        let linked = written.and_then(|()| fs::hard_link(&tmp, &path));
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(KeystoreError::AlreadyExists),
            Err(e) => Err(io(e)),
        }
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        match fs::remove_file(self.path(slot)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Platform
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

fn protect(secret: &[u8; 32], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = blob(secret)?;
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

fn unprotect(sealed: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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
        return Err(KeystoreError::Corrupt(
            "the slot does not open for this user on this machine",
        ));
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
