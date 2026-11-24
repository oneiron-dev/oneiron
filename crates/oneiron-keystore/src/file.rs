//! Unix: one 0600 file per slot in a 0700 directory of its own. It is the
//! platform tier on Unix systems other than Apple, and on Apple the file tier
//! an owner chooses for a build the keychain will not serve
//! ([`crate::file_keystore`]); Time Machine does not honour the tag below.
//!
//! The directory must lie outside every vault directory, because a vault's
//! checkpoints and backups copy what is inside it. It carries a `CACHEDIR.TAG`, so
//! backup tools that honour the tag (borg, restic, tar `--exclude-caches`) skip it.
//! A lost slot costs only re-wrapping. Linux has no standard store that is both
//! persistent and never backed up. This adapter is the nearest one.
//!
//! The same directory keeps the bytes the engine sealed under a device PIN
//! ([`SealedBytesStore`]): one 0600 file per name, `<name>.sealed`, which no
//! slot reads.
//!
//! macOS keeps a file's access control list apart from its mode bits, so a
//! 0700 directory or a 0600 file may still let another user read it. On Apple
//! a directory or a file that carries one is refused, as one with open mode
//! bits is (a Linux ACL shows in the group bits, which the mode check reads).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::sealed_bytes::check_sealed_len;
use crate::{
    DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, Result, SEALED_BYTES_MAX,
    SealedBytesName, SealedBytesStore,
};

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
        #[cfg(target_vendor = "apple")]
        apple_acl::refuse(&File::open(&dir).map_err(io)?, DIR_ACL)?;
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

    /// The file of one sealed value, under a suffix no slot file has.
    fn sealed_path(&self, name: &SealedBytesName) -> PathBuf {
        self.dir.join(sealed_file_name(name))
    }

    /// The key directory, checked and canonical: the hardware tier keeps its
    /// sealed slots here too, under their own suffix (OF-168).
    #[cfg(target_os = "linux")]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    fn sync_dir(&self) -> Result<()> {
        File::open(&self.dir).and_then(|d| d.sync_all()).map_err(io)
    }

    /// A private temporary file holding `bytes`, beside the file it will
    /// become. `stem` is that file's name; the open-time sweep removes a
    /// temporary file a dead process left under any stem. On Apple a file
    /// that inherited an access control list from the directory is refused
    /// before `bytes` reach it.
    fn write_temp(&self, stem: &str, bytes: &[u8]) -> (PathBuf, std::io::Result<()>) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = self
            .dir
            .join(format!(".{stem}.{}.{nanos}.tmp", std::process::id()));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut file| {
                #[cfg(target_vendor = "apple")]
                apple_acl::refuse_inherited(&file)?;
                file.write_all(bytes)?;
                file.sync_all()
            });
        (tmp, written)
    }

    /// Removes stale temporary files for one slot, or every slot (FIX 8019):
    /// those whose writer is gone ([`writer_alive`]), on macOS too.
    pub(crate) fn sweep_temps(&self, slot: Option<&KeystoreSlot>) {
        let wanted = slot.map(super::KeystoreSlot::name);
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
            } else if slot_part.split('.').any(str::is_empty) {
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
            if pid == own || writer_alive(pid) {
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
        #[cfg(target_vendor = "apple")]
        apple_acl::refuse(&file, SLOT_ACL)?;
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
        let (tmp, written) = self.write_temp(&slot.name(), secret);
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
        let (tmp, written) = self.write_temp(&slot.name(), secret);
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

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(self)
    }
}

/// `<name>.sealed`: the file of one sealed value in the key directory.
fn sealed_file_name(name: &SealedBytesName) -> String {
    format!("{}.sealed", name.name())
}

impl SealedBytesStore for LocalFileKeystore {
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>> {
        let file = match File::open(self.sealed_path(name)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(KeystoreError::Corrupt("the sealed file is open to others"));
        }
        #[cfg(target_vendor = "apple")]
        apple_acl::refuse(&file, SEALED_ACL)?;
        let mut sealed = Vec::new();
        file.take(SEALED_BYTES_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.is_empty() || sealed.len() > SEALED_BYTES_MAX {
            return Err(KeystoreError::Corrupt(
                "the sealed file is empty or longer than a home keeps",
            ));
        }
        Ok(Some(sealed))
    }

    /// Writes a private temporary file, then renames it into place: one
    /// rename, so a reader opens the old file or the new one, and a crash
    /// leaves one of the two whole.
    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<()> {
        check_sealed_len(sealed)?;
        let (tmp, written) = self.write_temp(&sealed_file_name(name), sealed);
        let renamed = written.and_then(|()| fs::rename(&tmp, self.sealed_path(name)));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        renamed.map_err(io)?;
        self.sync_dir()
    }

    fn delete_sealed(&self, name: &SealedBytesName) -> Result<()> {
        match fs::remove_file(self.sealed_path(name)) {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }
}

fn io(e: std::io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}

/// `ESRCH`, "no such process": 3 on Linux, macOS and the BSDs.
const ESRCH: i32 = 3;

unsafe extern "C" {
    // POSIX signal.h, in the C library of every Unix system.
    fn kill(pid: i32, signal: i32) -> i32;
}

/// Whether the process `pid`, which named a temporary file, may still be
/// writing it: `/proc/<pid>` where the system mounts `/proc` (Linux), else
/// the null signal ([`signal_finds_process`]; macOS has no `/proc`).
fn writer_alive(pid: u32) -> bool {
    if Path::new("/proc").exists() {
        return Path::new(&format!("/proc/{pid}")).exists();
    }
    signal_finds_process(pid)
}

/// `kill(pid, 0)`: the null signal, which sends nothing and only asks whether
/// `pid` names a process. Every answer but "no such process" keeps the
/// writer's files: `EPERM` names another user's live process. 0 and values
/// past `pid_t` name a process group or every process, never one writer.
fn signal_finds_process(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return true;
    };
    if pid <= 0 {
        return true;
    }
    // SAFETY: `kill` reads its two integer arguments and no memory of this
    // process; signal 0 delivers nothing to `pid`.
    let answer = unsafe { kill(pid, 0) };
    answer == 0 || std::io::Error::last_os_error().raw_os_error() != Some(ESRCH)
}

#[cfg(target_vendor = "apple")]
const DIR_ACL: &str = "the key directory is open to others through an access control list";
#[cfg(target_vendor = "apple")]
const SLOT_ACL: &str = "the slot file is open to others through an access control list";
#[cfg(target_vendor = "apple")]
const SEALED_ACL: &str = "the sealed file is open to others through an access control list";

/// macOS access control lists (sys/acl.h), which the mode bits do not show:
/// `ls -le` lists them and `chmod -N` removes them.
#[cfg(target_vendor = "apple")]
mod apple_acl {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;

    use crate::{KeystoreError, Result};

    /// `ACL_TYPE_EXTENDED`, the one ACL type macOS keeps.
    const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
    /// `ACL_FIRST_ENTRY`.
    const ACL_FIRST_ENTRY: i32 = 0;
    /// `ENOENT`: the answer for a file that carries no access control list.
    const ENOENT: i32 = 2;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, acl_type: u32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }

    /// Whether `file` carries an access control list with at least one entry.
    fn has_entries(file: &File) -> std::io::Result<bool> {
        // SAFETY: the descriptor is open for as long as `file` is borrowed,
        // and the call only reads the ACL of the file it names.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(ENOENT) => Ok(false),
                _ => Err(error),
            };
        }
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is the live list the call above returned, and `entry`
        // is a writable place for the one entry pointer it answers.
        let first = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
        // SAFETY: `acl` came from `acl_get_fd_np`, is freed once here, and
        // neither it nor `entry`, which points into it, is used after.
        unsafe { acl_free(acl) };
        Ok(first == 0)
    }

    /// `refusal` when `file` carries an access control list.
    pub(super) fn refuse(file: &File, refusal: &'static str) -> Result<()> {
        match has_entries(file) {
            Ok(false) => Ok(()),
            Ok(true) => Err(KeystoreError::Corrupt(refusal)),
            Err(e) => Err(super::io(e)),
        }
    }

    /// A refusal of a new key file that inherited an access control list.
    pub(super) fn refuse_inherited(file: &File) -> std::io::Result<()> {
        if has_entries(file)? {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "the new key file inherited an access control list",
            ));
        }
        Ok(())
    }
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

    /// `true`'s process id once it has exited and been reaped: no process.
    #[allow(
        clippy::disallowed_methods,
        reason = "a test starts one child for a process id that is gone"
    )]
    fn gone_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// FIX 8019 where there is no `/proc` (macOS): the null signal tells a
    /// live writer from a gone one, and keeps the files of any pid it cannot
    /// name as one process.
    #[test]
    fn the_null_signal_tells_a_live_writer_from_a_gone_one() {
        assert!(signal_finds_process(std::process::id()));
        assert!(!signal_finds_process(gone_pid()));
        assert!(signal_finds_process(0));
        assert!(signal_finds_process(u32::MAX));
    }

    /// FIX 8019 on every Unix system, macOS included: a copy of the seed that
    /// a writer which died between its link and its unlink left goes with
    /// the slot's delete. A live writer's file stays.
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "a test starts one child that stands for a live writer"
    )]
    fn delete_removes_a_dead_writers_copy_of_the_seed() {
        let root = tempfile::tempdir().unwrap();
        let keys = LocalFileKeystore::open(&root.path().join("keys"), &[]).unwrap();
        keys.create(&slot(), &[1; 32]).unwrap();
        let copy = |pid: u32| keys.dir.join(format!(".{}.{pid}.1.tmp", slot().name()));
        let dead = copy(gone_pid());
        fs::hard_link(keys.path(&slot()), &dead).unwrap();
        let mut live_writer = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let live = copy(live_writer.id());
        fs::hard_link(keys.path(&slot()), &live).unwrap();
        keys.delete(&slot()).unwrap();
        let live_kept = live.exists();
        live_writer.kill().unwrap();
        live_writer.wait().unwrap();
        assert!(
            !dead.exists(),
            "a dead writer's copy of the seed is removed"
        );
        assert!(live_kept, "a live writer's file is kept");
    }

    /// macOS keeps access control lists apart from the mode bits: a grant to
    /// another user on a 0600 slot or a 0700 directory is refused, and a file
    /// that would inherit the directory's grant never receives a seed.
    #[cfg(target_vendor = "apple")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "macOS sets an access control list through chmod +a"
    )]
    fn an_access_control_list_on_the_directory_or_a_file_is_refused() {
        let grant = |path: &Path, rule: &str| {
            let status = std::process::Command::new("/bin/chmod")
                .arg("+a")
                .arg(rule)
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success(), "chmod +a {rule:?}");
        };
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let keys = LocalFileKeystore::open(&dir, &[]).unwrap();
        keys.create(&slot(), &[1; 32]).unwrap();
        grant(&keys.path(&slot()), "everyone allow read");
        assert_eq!(
            keys.get(&slot()).unwrap_err(),
            KeystoreError::Corrupt(SLOT_ACL)
        );
        grant(&keys.dir, "everyone allow list,search,file_inherit");
        assert_eq!(
            LocalFileKeystore::open(&dir, &[]).unwrap_err(),
            KeystoreError::Corrupt(DIR_ACL)
        );
        let other = KeystoreSlot {
            vault_id: [8; 32],
            ..slot()
        };
        assert!(keys.create(&other, &[2; 32]).is_err());
        assert_eq!(keys.get(&other).unwrap(), None);
    }
}
