//! Unix (not Apple): one 0600 file per slot in a 0700 directory of its own.
//!
//! The directory must lie outside every vault directory, because a vault's
//! checkpoints and backups copy what is inside it. It carries a `CACHEDIR.TAG`, so
//! backup tools that honour the tag (borg, restic, tar `--exclude-caches`) skip it.
//! A lost slot costs only re-wrapping. Linux has no standard store that is both
//! persistent and never backed up. This adapter is the nearest one.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, Result};

const CACHEDIR_TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n\
# This directory holds this machine's own key slots (oneiron-keystore).\n\
# They must not be backed up or copied to another machine.\n";

/// One file per slot under `dir`.
#[derive(Debug)]
pub struct LocalFileKeystore {
    dir: PathBuf,
}

impl LocalFileKeystore {
    /// Creates `dir` (0700) when absent. It refuses a directory that others can read,
    /// and one inside any of `vault_dirs`.
    pub fn open(dir: &Path, vault_dirs: &[&Path]) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io)?;
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
        let meta = fs::metadata(&dir).map_err(io)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(KeystoreError::Corrupt(
                "the key directory is open to others",
            ));
        }
        let tag = dir.join("CACHEDIR.TAG");
        if !tag.exists() {
            fs::write(&tag, CACHEDIR_TAG).map_err(io)?;
        }
        let this = Self { dir };
        // FIX 8019: sweep every slot's stale temporary files once.
        this.sweep_temps(None);
        Ok(this)
    }

    fn path(&self, slot: &KeystoreSlot) -> PathBuf {
        self.dir.join(format!("{}.key", slot.name()))
    }

    fn sync_dir(&self) -> Result<()> {
        File::open(&self.dir).and_then(|d| d.sync_all()).map_err(io)
    }

    /// A private temporary file holding `secret`, beside the slot's file.
    fn write_temp(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> (PathBuf, std::io::Result<()>) {
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
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(secret)?;
                file.sync_all()
            });
        (tmp, written)
    }

    /// Removes stale temporary files for one slot, or every slot (FIX 8019).
    fn sweep_temps(&self, slot: Option<&KeystoreSlot>) {
        // Without /proc no pid is known gone, so every file is kept.
        if !Path::new("/proc").exists() {
            return;
        }
        let wanted = slot.map(|s| s.name());
        let own = std::process::id();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(name) => name,
                None => continue,
            };
            let after_dot = match name.strip_prefix('.') {
                Some(rest) => rest,
                None => continue,
            };
            let inner = match after_dot.strip_suffix(".tmp") {
                Some(inner) => inner,
                None => continue,
            };
            let (prefix, nanos_text) = match inner.rsplit_once('.') {
                Some(pair) => pair,
                None => continue,
            };
            let (slot_part, pid_text) = match prefix.rsplit_once('.') {
                Some(pair) => pair,
                None => continue,
            };
            if slot_part.is_empty() || pid_text.is_empty() || nanos_text.is_empty() {
                continue;
            }
            if let Some(wanted) = wanted.as_deref() {
                if slot_part != wanted {
                    continue;
                }
            } else if slot_part.split('.').any(|part| part.is_empty()) {
                continue;
            }
            if !pid_text.bytes().all(|b| b.is_ascii_digit())
                || !nanos_text.bytes().all(|b| b.is_ascii_digit())
            {
                continue;
            }
            let pid: u32 = match pid_text.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            if nanos_text.parse::<u128>().is_err() {
                continue;
            }
            if pid == own {
                continue;
            }
            if Path::new(&format!("/proc/{pid}")).exists() {
                continue;
            }
            let _ = fs::remove_file(entry.path());
        }
    }
}

impl DeviceKeystore for LocalFileKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let mut file = match File::open(self.path(slot)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(KeystoreError::Corrupt("the slot file is open to others"));
        }
        let mut bytes = Zeroizing::new([0u8; 33]);
        let mut len = 0;
        loop {
            match file.read(&mut bytes[len..]).map_err(io)? {
                0 => break,
                n => len += n,
            }
            if len == bytes.len() {
                break;
            }
        }
        if len != 32 {
            return Err(KeystoreError::Corrupt("the slot is not 32 bytes"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[..32]);
        Ok(Some(secret))
    }

    /// Writes a private temporary file, then links it into place. A crash leaves
    /// either no slot or a whole one, and the link never replaces a filled slot.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        // FIX 8019: sweep this slot's stale temporary files before writing.
        self.sweep_temps(Some(slot));
        let path = self.path(slot);
        let (tmp, written) = self.write_temp(slot, secret);
        let linked = written.and_then(|()| fs::hard_link(&tmp, &path));
        // FIX 8019: a failed removal is swept by a later open, create or delete.
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(KeystoreError::AlreadyExists),
            Err(e) => Err(io(e)),
        }
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        match fs::remove_file(self.path(slot)) {
            Ok(()) => {
                // FIX 8019: sweep this slot's stale temporary files, then sync.
                self.sweep_temps(Some(slot));
                self.sync_dir()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // FIX 8019: no slot file, still sweep this slot's stale files.
                self.sweep_temps(Some(slot));
                Ok(())
            }
            Err(e) => Err(io(e)),
        }
    }

    /// Writes a private temporary file, then renames it over the filled slot:
    /// one rename, so a reader opens the old file or the new one, never none.
    /// An empty slot is `Ok(false)` and nothing is written; a delete racing
    /// the rename may leave the slot holding `secret`.
    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let path = self.path(slot);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Err(KeystoreError::Corrupt("the slot is not a file")),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io(e)),
        }
        let (tmp, written) = self.write_temp(slot, secret);
        let renamed = written.and_then(|()| fs::rename(&tmp, &path));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        renamed.map_err(io)?;
        self.sync_dir()?;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }
}

fn io(e: std::io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot() -> KeystoreSlot {
        KeystoreSlot {
            vault_id: [7; 32],
            install: [3; 16],
            kind: crate::SlotKind::MachineEncryption,
        }
    }

    /// Done means (ruling fix 9): the machine secret stays on this machine. It is
    /// written private, never overwritten, and never kept inside a vault directory,
    /// whose checkpoints and backups travel.
    #[test]
    fn a_slot_is_private_create_only_and_kept_out_of_the_vault() {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("vault");
        fs::create_dir(&vault).unwrap();
        assert_eq!(
            LocalFileKeystore::open(&vault.join("keys"), &[&vault]).unwrap_err(),
            KeystoreError::Unavailable("the key directory is inside a vault directory")
        );
        let keys = LocalFileKeystore::open(&root.path().join("keys"), &[&vault]).unwrap();
        assert_eq!(keys.get(&slot()).unwrap(), None);
        keys.create(&slot(), &[1; 32]).unwrap();
        assert_eq!(
            keys.create(&slot(), &[2; 32]).unwrap_err(),
            KeystoreError::AlreadyExists
        );
        assert_eq!(*keys.get(&slot()).unwrap().unwrap(), [1; 32]);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&keys.path(&slot())), 0o600);
        assert_eq!(mode(&keys.dir), 0o700);
        assert!(keys.dir.join("CACHEDIR.TAG").exists());
        let leftovers = fs::read_dir(&keys.dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        fs::set_permissions(keys.path(&slot()), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(keys.get(&slot()), Err(KeystoreError::Corrupt(_))));
        keys.delete(&slot()).unwrap();
        keys.delete(&slot()).unwrap();
        assert_eq!(keys.get(&slot()).unwrap(), None);
    }
}
