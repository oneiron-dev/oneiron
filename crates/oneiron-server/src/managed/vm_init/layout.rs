//! The vault VM's disk layout, provision record, UID table and socket
//! directories, as the root bootstrap sets them up before the engine starts.
//!
//! - `/vault`, the vault disk's root: root-owned, mode 0711, never chowned
//!   to the vault's UID and never encrypted itself.
//! - `/vault/control`: root-only (0700), holding the provision record
//!   ([`VM_PROVISION_RECORD`], 0600), which names the binding the disk was
//!   provisioned for and no key.
//! - [`VM_GUEST_STORAGE_DIR`] and [`VM_GUEST_KEYS_DIR`]: the vault UID's
//!   (UID:GID 0700), each under the fscrypt v2 policy of the provisioned
//!   key, set while empty. [`VM_GUEST_DATA_DIR`] lies inside the storage and
//!   inherits its policy.
//! - The UID table at [`vault_uids::PATH`], on the tmpfs the image's init
//!   mounts at its directory: one row binding the UID to the vault at its
//!   data directory, rebuilt from the host's binding on every cold boot.
//!
//! A cold restore's boot (FIX 6584) lays out the same, except that the
//! data directory is left absent, for the restore to make, and the UID
//! table's row names it at the held storage's path. An inspection's boot
//! lays out nothing: it only reads the control directory's record.
//! - `/run/oneiron` and [`VM_VOICE_DIR`], the engine's socket directories:
//!   the vault UID's, 0700.
//! - When the guests' container runtime is prepared (FIX 7671, the sibling
//!   `guest_runtime`), `/vault/storage/container` and the container CLI's
//!   [`VM_GUEST_CONTAINER_HOME`] and [`VM_GUEST_CONTAINER_RUNTIME_DIR`] in
//!   it: the vault UID's, 0700, beside the data directory and never in it.
//!   The runtime directory is emptied on each of those boots (FIX 8936).
//!
//! A directory that already holds content keeps its policy, owner and mode
//! or is refused: nothing is re-encrypted or re-owned. Every look below the
//! vault root goes through held directories, opened without following a
//! link. The managed open's own isolation gates are unchanged; this only
//! supplies what they check.

use super::Refusal;
use super::fscrypt::{self, KeyIdentifier, Policy};
use oneiron_vault_contract::vault_uids::{self, VaultUidRow};
use oneiron_vault_contract::vm::{
    VM_GUEST_CONTAINER_HOME, VM_GUEST_CONTAINER_RUNTIME_DIR, VM_GUEST_DATA_DIR, VM_GUEST_KEYS_DIR,
    VM_GUEST_STORAGE_DIR, VM_VOICE_DIR,
};
use oneiron_vault_contract::vm_provision::{VM_PROVISION_RECORD, VmProvision, VmProvisionFailure};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::fs::{File, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::Path;

/// The vault disk's mountpoint, and the drive the image's init mounts there.
const VAULT_ROOT: &str = "/vault";
const VAULT_DEVICE: &str = "/dev/vdb";
/// The leaves of [`VM_GUEST_STORAGE_DIR`], [`VM_GUEST_DATA_DIR`],
/// [`VM_GUEST_KEYS_DIR`] and [`VM_PROVISION_RECORD`].
pub(super) const STORAGE_LEAF: &str = "storage";
pub(super) const DATA_LEAF: &str = "data";
const KEYS_LEAF: &str = "keys";
const CONTROL_LEAF: &str = "control";
const RECORD_LEAF: &str = "vm-provision.json";
/// The container CLI directories' parent in the storage, and the leaves
/// of [`VM_GUEST_CONTAINER_HOME`] and [`VM_GUEST_CONTAINER_RUNTIME_DIR`] in
/// it.
const CONTAINER_LEAF: &str = "container";
const CONTAINER_DIR: &str = "/vault/storage/container";
const HOME_LEAF: &str = "home";
const RUNTIME_LEAF: &str = "runtime";
/// The engine's socket directory, the parent of [`VM_VOICE_DIR`].
const RUN_DIR: &str = "/run/oneiron";
/// The longest provision record read back: it is a few short fields.
const MAX_RECORD_BYTES: u64 = 4096;
/// ext4's superblock: its offset, magic, `encrypt` incompat feature bit and
/// the offsets of the fields read here.
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xef53;
const EXT4_INCOMPAT_ENCRYPT: u32 = 0x1_0000;

/// What a vault disk was provisioned for, as its record keeps it. No key
/// byte is in it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionRecord {
    vault: String,
    guest_uid: u32,
    vault_disk_uuid: String,
    fscrypt_key_identifier: String,
}

impl ProvisionRecord {
    pub(super) fn of(frame: &VmProvision) -> Self {
        Self {
            vault: frame.vault.clone(),
            guest_uid: frame.binding.guest_uid,
            vault_disk_uuid: frame.binding.vault_disk_uuid.clone(),
            fscrypt_key_identifier: frame.binding.fscrypt_key_identifier.clone(),
        }
    }
}

fn mismatch(detail: impl Into<String>) -> Refusal {
    Refusal::new(VmProvisionFailure::StorageMismatch, detail)
}

fn failed(what: &str) -> impl FnOnce(std::io::Error) -> Refusal + '_ {
    move |error| {
        Refusal::new(
            VmProvisionFailure::ProvisionFailed,
            format!("{what}: {error}"),
        )
    }
}

fn private(mode: u32) -> Permissions {
    Permissions::from_mode(mode)
}

/// The vault root, held: the disk the image's init mounted at `/vault`.
pub(super) fn open_vault_root() -> Result<File, Refusal> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(VAULT_ROOT)
        .map_err(failed("opening /vault"))
}

/// Refuses unless `root` is the vault drive's filesystem, ext4 with its
/// `encrypt` feature, whose UUID is `uuid`.
pub(super) fn check_disk(root: &File, uuid: &str) -> Result<(), Refusal> {
    use std::os::unix::fs::FileExt;
    let mounted = root.metadata().map_err(failed("reading /vault"))?;
    let device = std::fs::metadata(VAULT_DEVICE).map_err(failed("reading /dev/vdb"))?;
    if !device.file_type().is_block_device() || device.rdev() != mounted.dev() {
        return Err(Refusal::new(
            VmProvisionFailure::DiskMismatch,
            "/vault is not the vault drive /dev/vdb",
        ));
    }
    let mut superblock = [0u8; 1024];
    File::open(VAULT_DEVICE)
        .and_then(|drive| drive.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET))
        .map_err(failed("reading the vault drive's superblock"))?;
    if u16::from_le_bytes([superblock[0x38], superblock[0x39]]) != EXT4_MAGIC {
        return Err(Refusal::new(
            VmProvisionFailure::DiskMismatch,
            "the vault drive is not ext4",
        ));
    }
    let incompat = u32::from_le_bytes([
        superblock[0x60],
        superblock[0x61],
        superblock[0x62],
        superblock[0x63],
    ]);
    if incompat & EXT4_INCOMPAT_ENCRYPT == 0 {
        return Err(Refusal::new(
            VmProvisionFailure::FscryptUnavailable,
            "the vault drive's ext4 lacks the encrypt feature",
        ));
    }
    let id = &superblock[0x68..0x78];
    let hex = oneiron_vault_contract::hex;
    let found = format!(
        "{}-{}-{}-{}-{}",
        hex(&id[..4]),
        hex(&id[4..6]),
        hex(&id[6..8]),
        hex(&id[8..10]),
        hex(&id[10..])
    );
    if found != uuid {
        return Err(Refusal::new(
            VmProvisionFailure::DiskMismatch,
            format!("the vault drive's filesystem UUID is {found}, not the binding's"),
        ));
    }
    Ok(())
}

/// The child directory `leaf` of `parent`, made with `mode` when absent and
/// opened without following a link. `path` names it in a refusal.
fn open_dir(parent: &File, leaf: &str, path: &str, mode: u32) -> Result<File, Refusal> {
    match rustix::fs::mkdirat(parent, leaf, Mode::from_raw_mode(mode)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(failed(path)(error.into())),
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(parent, leaf, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(Errno::LOOP | Errno::NOTDIR) => Err(mismatch(format!("{path} is not a directory"))),
        Err(error) => Err(failed(path)(error.into())),
    }
}

fn is_empty(dir: &File) -> std::io::Result<bool> {
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Makes the vault root root's (0711, never re-owned) and opens its
/// root-only control directory.
pub(super) fn open_control(root: &File) -> Result<File, Refusal> {
    let metadata = root.metadata().map_err(failed("reading /vault"))?;
    if metadata.uid() != 0 {
        return Err(mismatch("the vault disk's root is not root-owned"));
    }
    root.set_permissions(private(0o711))
        .map_err(failed("setting /vault's mode"))?;
    let control = open_dir(root, CONTROL_LEAF, "/vault/control", 0o700)?;
    let metadata = control
        .metadata()
        .map_err(failed("reading /vault/control"))?;
    if metadata.uid() != 0 {
        return Err(mismatch("/vault/control is not root-owned"));
    }
    control
        .set_permissions(private(0o700))
        .map_err(failed("setting /vault/control's mode"))?;
    Ok(control)
}

/// The vault root's control directory when there is one, opened without
/// making it or changing a mode, and refused unless it is root's.
pub(super) fn existing_control(root: &File) -> Result<Option<File>, Refusal> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let control = match rustix::fs::openat(root, CONTROL_LEAF, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP | Errno::NOTDIR) => {
            return Err(mismatch("/vault/control is not a directory"));
        }
        Err(error) => return Err(failed("/vault/control")(error.into())),
    };
    let metadata = control
        .metadata()
        .map_err(failed("reading /vault/control"))?;
    if metadata.uid() != 0 {
        return Err(mismatch("/vault/control is not root-owned"));
    }
    Ok(Some(control))
}

/// Whether the disk already records `record`: `false` when it records none,
/// refused when it records another binding or its record is not root's
/// alone.
pub(super) fn recorded(control: &File, record: &ProvisionRecord) -> Result<bool, Refusal> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = match rustix::fs::openat(control, RECORD_LEAF, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(false),
        Err(error) => return Err(failed(VM_PROVISION_RECORD)(error.into())),
    };
    let metadata = file.metadata().map_err(failed(VM_PROVISION_RECORD))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(mismatch(format!(
            "{VM_PROVISION_RECORD} is not a root-only regular file"
        )));
    }
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES)
        .read_to_string(&mut text)
        .map_err(failed(VM_PROVISION_RECORD))?;
    let found: ProvisionRecord = serde_json::from_str(&text)
        .map_err(|_| mismatch(format!("{VM_PROVISION_RECORD} does not parse")))?;
    if found != *record {
        return Err(mismatch(
            "the vault disk was provisioned for another vault, UID, disk or key",
        ));
    }
    Ok(true)
}

/// Writes `record` whole beside its final name, root:root 0600, and renames
/// it into place.
pub(super) fn write_record(control: &File, record: &ProvisionRecord) -> Result<(), Refusal> {
    let text = serde_json::to_string(record)
        .map_err(|error| failed(VM_PROVISION_RECORD)(std::io::Error::other(error)))?;
    publish(control, RECORD_LEAF, text.as_bytes(), 0o600).map_err(failed(VM_PROVISION_RECORD))
}

/// Writes `bytes` to a temporary file in `dir`, gives it `mode`, syncs it
/// and renames it to `leaf`, so a reader sees the old file or the new one.
fn publish(dir: &File, leaf: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let temporary = format!(".{leaf}.tmp");
    match rustix::fs::unlinkat(dir, temporary.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(rustix::fs::openat(
        dir,
        temporary.as_str(),
        flags,
        Mode::from_raw_mode(mode),
    )?);
    file.set_permissions(private(mode))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::renameat(dir, temporary.as_str(), dir, leaf)?;
    dir.sync_all()
}

/// The directory `leaf` of `parent` under the provisioned key's policy,
/// owned by `uid` with mode 0700. An empty one is made so, policy first; one
/// with content must already be so.
fn encrypted_dir(
    parent: &File,
    leaf: &str,
    path: &str,
    uid: u32,
    identifier: &KeyIdentifier,
) -> Result<File, Refusal> {
    let dir = open_dir(parent, leaf, path, 0o700)?;
    let empty = is_empty(&dir).map_err(failed(path))?;
    match fscrypt::policy(&dir) {
        Ok(Policy::Ours(found)) if found == *identifier => {}
        Ok(Policy::Plaintext) if empty => {
            fscrypt::set_policy(&dir, identifier).map_err(failed(path))?;
        }
        Ok(Policy::Plaintext) => {
            return Err(mismatch(format!("{path} is plaintext and not empty")));
        }
        Ok(Policy::Ours(_) | Policy::Other) => {
            return Err(mismatch(format!("{path} is under another fscrypt policy")));
        }
        Err(error) if fscrypt::unsupported(&error) => {
            return Err(Refusal::new(
                VmProvisionFailure::FscryptUnavailable,
                format!("{path}: {error}"),
            ));
        }
        Err(error) => return Err(failed(path)(error)),
    }
    uid_owned(dir, empty, path, uid)
}

/// `dir` given to `uid` with mode 0700 when it is `empty`; else refused
/// unless it is already so. Nothing in it is re-owned.
fn uid_owned(dir: File, empty: bool, path: &str, uid: u32) -> Result<File, Refusal> {
    if empty {
        fchown(&dir, Some(uid), Some(uid)).map_err(failed(path))?;
        dir.set_permissions(private(0o700)).map_err(failed(path))?;
        return Ok(dir);
    }
    let metadata = dir.metadata().map_err(failed(path))?;
    if metadata.uid() != uid || metadata.gid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(mismatch(format!(
            "{path} is not the vault UID's with mode 0700"
        )));
    }
    Ok(dir)
}

/// Lays out the encrypted storage, its data directory (`with_data`) and the
/// key directory for `uid` under the key `identifier` names, which the
/// keyring holds. Every encrypted handle is closed when this returns.
pub(super) fn lay_out_storage(
    root: &File,
    uid: u32,
    identifier: &KeyIdentifier,
    with_data: bool,
) -> Result<(), Refusal> {
    let storage = encrypted_dir(root, STORAGE_LEAF, VM_GUEST_STORAGE_DIR, uid, identifier)?;
    if with_data {
        encrypted_dir(&storage, DATA_LEAF, VM_GUEST_DATA_DIR, uid, identifier)?;
    }
    encrypted_dir(root, KEYS_LEAF, VM_GUEST_KEYS_DIR, uid, identifier)?;
    Ok(())
}

/// Makes the guests' container CLI directories (FIX 7671) in the encrypted
/// storage, outside the data directory: their parent, then
/// [`VM_GUEST_CONTAINER_HOME`] and [`VM_GUEST_CONTAINER_RUNTIME_DIR`] in it,
/// each the vault UID's with mode 0700 and under the storage's inherited
/// policy. An empty one is made so; one with content must already be so.
/// The runtime directory is then emptied, itself kept with its owner and
/// mode: the CLI's pause process id, locks and sockets are this boot's own,
/// never an earlier boot's (FIX 8936). `HOME` and the image store in it are
/// kept.
pub(super) fn own_container_dirs(uid: u32) -> Result<(), Refusal> {
    let root = open_vault_root()?;
    let storage = open_dir(&root, STORAGE_LEAF, VM_GUEST_STORAGE_DIR, 0o700)?;
    let parent = owned_child(&storage, CONTAINER_LEAF, CONTAINER_DIR, uid)?;
    owned_child(&parent, HOME_LEAF, VM_GUEST_CONTAINER_HOME, uid)?;
    let runtime = owned_child(&parent, RUNTIME_LEAF, VM_GUEST_CONTAINER_RUNTIME_DIR, uid)?;
    empty_dir(&runtime).map_err(failed(VM_GUEST_CONTAINER_RUNTIME_DIR))?;
    Ok(())
}

/// Removes everything in the held `dir` and keeps `dir`: each entry is
/// unlinked without following a link, a directory once it is emptied the
/// same way through its own held handle.
fn empty_dir(dir: &File) -> std::io::Result<()> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            names.push(entry.file_name().to_owned());
        }
    }
    for name in &names {
        let stat = rustix::fs::statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let child = rustix::fs::openat(dir, name.as_c_str(), flags, Mode::empty())?;
            empty_dir(&File::from(child))?;
            rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR)?;
        } else {
            rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::empty())?;
        }
    }
    Ok(())
}

/// The child directory `leaf` of `parent`, made when absent, as
/// [`uid_owned`] leaves it.
fn owned_child(parent: &File, leaf: &str, path: &str, uid: u32) -> Result<File, Refusal> {
    let dir = open_dir(parent, leaf, path, 0o700)?;
    let empty = is_empty(&dir).map_err(failed(path))?;
    uid_owned(dir, empty, path, uid)
}

/// Installs the guest's UID table: one row allocating `uid` to `vault` at
/// the data directory, root:root [`vault_uids::MODE`], in the root-only
/// directory the image's init mounted a tmpfs on. For a cold restore
/// (`restoring`) the data directory is not there yet: the row names it
/// below the storage, whose path is the one checked.
pub(super) fn install_uid_table(vault: &str, uid: u32, restoring: bool) -> Result<(), Refusal> {
    let table_path = Path::new(vault_uids::PATH);
    let (Some(parent), Some(leaf)) = (
        table_path.parent(),
        table_path.file_name().and_then(std::ffi::OsStr::to_str),
    ) else {
        return Err(failed(vault_uids::PATH)(std::io::Error::other(
            "the UID table has no directory",
        )));
    };
    let data_dir = if restoring {
        std::fs::canonicalize(VM_GUEST_STORAGE_DIR)
            .map(|storage| storage.join(DATA_LEAF))
            .map_err(failed(VM_GUEST_STORAGE_DIR))?
    } else {
        std::fs::canonicalize(VM_GUEST_DATA_DIR).map_err(failed(VM_GUEST_DATA_DIR))?
    };
    if data_dir != Path::new(VM_GUEST_DATA_DIR) {
        return Err(mismatch(format!("{VM_GUEST_DATA_DIR} is not canonical")));
    }
    let table = vault_uids::serialize(&[VaultUidRow {
        uid,
        vault: vault.to_owned(),
        data_dir,
    }])
    .map_err(|error| failed(vault_uids::PATH)(std::io::Error::other(error)))?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(failed(vault_uids::PATH))?;
    let metadata = dir.metadata().map_err(failed(vault_uids::PATH))?;
    if metadata.uid() != vault_uids::OWNER_UID
        || metadata.mode() & vault_uids::REFUSED_MODE_BITS != 0
    {
        return Err(failed(vault_uids::PATH)(std::io::Error::other(
            "the UID table's directory is not root's alone",
        )));
    }
    publish(&dir, leaf, table.as_bytes(), vault_uids::MODE).map_err(failed(vault_uids::PATH))
}

/// Gives the engine its socket directories, `/run/oneiron` and the voice
/// directory in it: the vault UID's, 0700, on the guest's `/run` tmpfs.
pub(super) fn own_run_dirs(uid: u32) -> Result<(), Refusal> {
    let run = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/run")
        .map_err(failed("/run"))?;
    let Some(voice_leaf) = Path::new(VM_VOICE_DIR)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
    else {
        return Err(failed(VM_VOICE_DIR)(std::io::Error::other("no leaf")));
    };
    let sockets = open_dir(&run, "oneiron", RUN_DIR, 0o700)?;
    let voice = open_dir(&sockets, voice_leaf, VM_VOICE_DIR, 0o700)?;
    for (dir, path) in [(&sockets, RUN_DIR), (&voice, VM_VOICE_DIR)] {
        fchown(dir, Some(uid), Some(uid)).map_err(failed(path))?;
        dir.set_permissions(private(0o700)).map_err(failed(path))?;
    }
    Ok(())
}
