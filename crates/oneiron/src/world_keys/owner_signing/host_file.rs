//! The host-held home of this install's owner signing seed (FIX 843): one
//! owner-only file beside the vault, `.<vault dir name>.owner-signing-key`,
//! for a host whose `[keystore] backend = "off"`. Like the page-seal mirror
//! it is never inside the vault, so no checkpoint or backup of the vault
//! carries it. It holds the 32-byte seed alone, and only the owner's
//! enrollment act writes it.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::super::page_seal::custody_root;
use super::super::{os_fill, refused};
use crate::error::Result;

const FILE_SUFFIX: &str = ".owner-signing-key";

/// Where the host holds this install's owner signing seed for the vault at
/// `vault_path` while its keystore is off (FIX 843):
/// `.<vault dir name>.owner-signing-key` beside the vault, owner-only.
pub fn owner_signing_key_path(vault_path: &Path) -> Result<PathBuf> {
    let root = custody_root(vault_path)?;
    let name = root
        .file_name()
        .ok_or_else(|| refused("a vault path names a directory"))?;
    let mut file = std::ffi::OsString::from(".");
    file.push(name);
    file.push(FILE_SUFFIX);
    Ok(root.with_file_name(file))
}

/// The seed the file at `path` holds; `None` when there is no file. A link,
/// a file others may read or one that is not 32 bytes is refused.
pub(super) fn read(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let mut file = match open_owner_only(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || open_to_others(&meta) {
        return Err(refused(
            "the owner signing key file is not a file only the owner may read",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 33]);
    let mut len = 0;
    loop {
        match file.read(&mut bytes[len..])? {
            0 => break,
            count => len += count,
        }
        if len == bytes.len() {
            break;
        }
    }
    if len != 32 {
        return Err(refused("the owner signing key file is not 32 bytes"));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[..32]);
    Ok(Some(seed))
}

/// The seed at `path`, made from the OS CSPRNG on first use: written to a
/// new owner-only temporary file, synced, then linked into place and the
/// directory synced. A crash leaves no file or a whole one, and the link
/// never replaces a seed already there, so a concurrent first use keeps the
/// first.
pub(super) fn seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(seed) = read(path)? {
        return Ok(seed);
    }
    let dir = path
        .parent()
        .ok_or_else(|| refused("a vault path names a directory"))?;
    let mut fresh = Zeroizing::new([0u8; 32]);
    os_fill(&mut fresh[..])?;
    let mut suffix = [0u8; 8];
    os_fill(&mut suffix)?;
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(
        ".{}.tmp",
        crate::entity_id::bytes_to_hex_lower(&suffix)
    ));
    let temp = PathBuf::from(temp);
    let linked = open_owner_only(&temp, true)
        .and_then(|mut file| {
            file.write_all(&fresh[..])?;
            file.sync_all()
        })
        .and_then(|()| fs::hard_link(&temp, path));
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => sync_dir(dir)?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    read(path)?.ok_or_else(|| refused("the owner signing key file is gone after it was written"))
}

/// Removes the file at `path`, the seed of a key the roster revoked; no
/// file is not an error.
pub(super) fn remove(path: &Path) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| refused("a vault path names a directory"))?;
    match fs::remove_file(path) {
        Ok(()) => sync_dir(dir),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Opens `path` without following a link: to read, or as a new owner-only
/// file to write.
fn open_owner_only(path: &Path, write_new: bool) -> std::io::Result<File> {
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
    options.open(path)
}

/// Whether anyone but the owner may read or write the file.
fn open_to_others(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o077 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}
