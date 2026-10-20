//! Fail-closed Linux fscrypt and root-owned UID allocation probes.
//!
//! The supervisor provisions the root-owned one-to-one UID allocation table;
//! its path, file shape and row codec are the contract's
//! [`oneiron_vault_contract::vault_uids`], which the supervisor writes with.
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use oneiron_vault_contract::vault_uids;
/// What the probe proved, about the one directory object it holds open.
#[derive(Debug)]
pub(super) struct IsolationEvidence {
    pub fscrypt: bool,
    pub dedicated_uid: bool,
    /// The probed directory, held open so its `(st_dev, st_ino)` stays this
    /// object's: the open binds it, never what the path names by then. `None`
    /// when the probe opened nothing; such evidence never counts as isolation.
    pub directory: Option<std::fs::File>,
}
impl IsolationEvidence {
    pub(super) fn admits(&self) -> bool {
        self.fscrypt && self.dedicated_uid
    }

    /// Each real-tenant facility this probe did not find, as the refusal
    /// names it: the data directory held as itself, its fscrypt policy, and
    /// a dedicated non-root UID that owns it. Empty only for evidence that
    /// counts as isolation.
    pub(super) fn missing(&self) -> Vec<&'static str> {
        [
            (
                self.directory.is_some(),
                "the data directory held open as itself (an absolute, canonical path to a directory)",
            ),
            (self.fscrypt, "an fscrypt policy on the data directory"),
            (
                self.dedicated_uid,
                "a dedicated non-root UID, allocated to this vault in the host's UID table, owning the data directory with no group or other access",
            ),
        ]
        .into_iter()
        .filter_map(|(found, facility)| (!found).then_some(facility))
        .collect()
    }
}
/// What reading a directory's fscrypt policy found.
#[cfg(target_os = "linux")]
pub(super) enum FscryptPolicy {
    /// A v1 or v2 policy.
    Present,
    /// No policy on the directory, or a filesystem without fscrypt.
    Absent,
    /// The read failed, or found a policy of a kind this build does not read.
    Unverified(std::io::Error),
}
/// The fscrypt policy of `dir`, a directory held open, as the kernel's GET
/// ioctl reads it: read-only, with no key needed. Neither the policy nor any
/// key is ever returned or kept.
#[cfg(target_os = "linux")]
pub(super) fn fscrypt_policy(dir: &std::fs::File) -> FscryptPolicy {
    match policy_version(dir) {
        Ok(Some(_)) => FscryptPolicy::Present,
        Ok(None) => FscryptPolicy::Absent,
        Err(error) => FscryptPolicy::Unverified(error),
    }
}
/// The version (1 or 2) of `dir`'s fscrypt policy, `None` where it has none,
/// as [`fscrypt_policy`] reads it.
#[cfg(target_os = "linux")]
fn policy_version(dir: &std::fs::File) -> std::io::Result<Option<u8>> {
    use std::os::fd::AsRawFd;
    // FS_IOC_GET_ENCRYPTION_POLICY_EX, linux/fscrypt.h. The kernel fills
    // policy_size and one of the v1 (12-byte) or v2 (24-byte) policy unions.
    #[repr(C)]
    struct Policy {
        size: u64,
        bytes: [u8; 24],
    }
    let mut policy = Policy {
        size: 24,
        bytes: [0; 24],
    };
    // The UAPI deliberately encodes __u8[9] (size + version), not sizeof(Policy).
    // Its request number stays 0xc0096616 even though this buffer is 32 bytes.
    // SAFETY: live directory fd; correctly sized/aligned writable UAPI buffer.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), 0xc0096616 as libc::c_ulong, &mut policy) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA | libc::EOPNOTSUPP | libc::ENOTTY) => Ok(None),
            _ => Err(error),
        };
    }
    match (policy.bytes[0], policy.size) {
        (0, 12) => Ok(Some(1)),
        (2, 24) => Ok(Some(2)),
        _ => Err(std::io::Error::other(
            "an fscrypt policy of a kind this build does not read",
        )),
    }
}
#[cfg(target_os = "linux")]
pub(super) fn probe(path: &Path, name: &str) -> IsolationEvidence {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let absent = || IsolationEvidence {
        fscrypt: false,
        dedicated_uid: false,
        directory: None,
    };
    let Ok(canonical) = path.canonicalize() else {
        return absent();
    };
    if canonical != path || !path.is_absolute() {
        return absent();
    }
    let Ok(dir) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
    else {
        return absent();
    };
    let Ok(metadata) = dir.metadata() else {
        return absent();
    };
    let fscrypt = matches!(fscrypt_policy(&dir), FscryptPolicy::Present);
    // SAFETY: geteuid has no pointer arguments or memory effects.
    let uid = unsafe { libc::geteuid() };
    IsolationEvidence {
        fscrypt,
        dedicated_uid: uid != 0
            && metadata.uid() == uid
            && metadata.mode() & 0o077 == 0
            && uid_allocated(uid, name, &canonical) == Some(true),
        directory: Some(dir),
    }
}
/// Whether the host's UID table allocates `uid` to `name` at `path`: `None`
/// when the table is not a regular root-owned file, opened without following
/// a link, that only root writes and that is within its size.
#[cfg(target_os = "linux")]
fn uid_allocated(uid: u32, name: &str, path: &Path) -> Option<bool> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let registry = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(vault_uids::PATH)
        .ok()?;
    let meta = registry.metadata().ok()?;
    if !meta.is_file()
        || meta.uid() != vault_uids::OWNER_UID
        || meta.mode() & vault_uids::REFUSED_MODE_BITS != 0
        || meta.len() > vault_uids::MAX_BYTES
    {
        return None;
    }
    let mut text = String::new();
    registry
        .take(vault_uids::MAX_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(uid_binding_matches(&text, uid, name, path))
}
#[cfg(not(target_os = "linux"))]
fn uid_allocated(_uid: u32, _name: &str, _path: &Path) -> Option<bool> {
    None
}
/// Whether `dir` carries an fscrypt v2 policy, the one a cold restore's
/// storage needs (the contract's CREATE isolation); fscrypt is Linux's.
#[cfg(target_os = "linux")]
fn fscrypt_v2(dir: &std::fs::File) -> bool {
    matches!(policy_version(dir), Ok(Some(2)))
}
#[cfg(not(target_os = "linux"))]
fn fscrypt_v2(_dir: &std::fs::File) -> bool {
    false
}
#[cfg(not(target_os = "linux"))]
pub(super) fn probe(_path: &Path, _name: &str) -> IsolationEvidence {
    IsolationEvidence {
        fscrypt: false,
        dedicated_uid: false,
        directory: None,
    }
}
/// Whether `table`, the UID table's text, allocates `uid` to `name` at
/// `path` one to one ([`vault_uids::binding_matches`]). A table that does
/// not parse allocates nothing.
#[cfg(any(target_os = "linux", test))]
fn uid_binding_matches(table: &str, uid: u32, name: &str, path: &Path) -> bool {
    vault_uids::parse(table).is_ok_and(|rows| vault_uids::binding_matches(&rows, uid, name, path))
}
/// What a cold restore's destination lacks, as its refusal names it.
const PARENT_HELD: &str =
    "the data directory's parent held open as itself (an absolute, canonical path to a directory)";
const FSCRYPT_V2: &str = "an fscrypt v2 policy on the vault's storage";
const DEDICATED_UID: &str = "a dedicated non-root UID, allocated to this vault at this data directory in the host's UID table, owning its storage with no group or other access";
/// A cold restore's destination (LC FIX 5384/5385): the directory its data
/// directory is made in, held open, and the data directory's name. Every
/// later look at the data directory goes through the held parent, never by
/// a path that could be swapped under it.
#[derive(Debug)]
pub(super) struct RestoreDestination {
    parent: std::fs::File,
    leaf: std::ffi::OsString,
    /// The data directory's absolute, canonical path: what the UID table
    /// binds.
    path: std::path::PathBuf,
}
/// Why a cold restore's destination is refused.
#[derive(Debug)]
pub(super) enum RestoreDestinationRefusal {
    /// The isolation a real tenant needs is not proven: each facility the
    /// probe did not find.
    Unproven(Vec<&'static str>),
    /// A name the restore makes is taken already, or could not be read.
    NotFresh,
    /// The data directory at its name is not one the restore can prove its
    /// own.
    Moved,
}
impl RestoreDestinationRefusal {
    /// What was refused, in closed names: never a path or an error's text.
    pub(super) fn what(&self) -> String {
        match self {
            Self::Unproven(missing) => format!(
                "the isolation a real tenant needs is not proven; missing: {}",
                missing.join("; ")
            ),
            Self::NotFresh => "a name the restore makes beside the data directory is taken".into(),
            Self::Moved => "the data directory is not the one the restore made".into(),
        }
    }
}
impl RestoreDestination {
    /// Proves the isolation a restored real tenant needs before anything is
    /// written: `data_dir`'s parent held open as itself, carrying an fscrypt
    /// v2 policy (which the data directory made in it takes), owned by this
    /// dedicated non-root UID with no group or other access, and the host's
    /// UID table allocating that UID to `name` at `data_dir`. Then every
    /// name the restore makes beside it is free: the data directory, its
    /// page-seal mirror and its key custody. A canary marker in the image
    /// waives none of it.
    pub(super) fn probe(data_dir: &Path, name: &str) -> Result<Self, RestoreDestinationRefusal> {
        use rustix::fs::{AtFlags, Mode, OFlags};
        let unheld = || RestoreDestinationRefusal::Unproven(vec![PARENT_HELD]);
        let (Some(parent), Some(leaf)) = (data_dir.parent(), data_dir.file_name()) else {
            return Err(unheld());
        };
        if !data_dir.is_absolute()
            || parent.join(leaf) != data_dir
            || parent.canonicalize().ok().as_deref() != Some(parent)
        {
            return Err(unheld());
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let held = rustix::fs::open(parent, flags, Mode::empty()).map_err(|_| unheld())?;
        let destination = Self {
            parent: std::fs::File::from(held),
            leaf: leaf.to_owned(),
            path: parent.join(leaf),
        };
        let missing = destination.missing_on(&destination.parent, name);
        if !missing.is_empty() {
            return Err(RestoreDestinationRefusal::Unproven(missing));
        }
        let mirror = oneiron::world_keys::page_seal_custody_path(data_dir)
            .ok()
            .and_then(|mirror| mirror.file_name().map(std::ffi::OsStr::to_owned))
            .ok_or(RestoreDestinationRefusal::NotFresh)?;
        // The key custody directory's name beside a vault, as the engine
        // names it (`.<data directory>.key-custody`).
        let mut custody = std::ffi::OsString::from(".");
        custody.push(leaf);
        custody.push(".key-custody");
        for taken in [leaf, mirror.as_os_str(), custody.as_os_str()] {
            match rustix::fs::statat(&destination.parent, taken, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(RestoreDestinationRefusal::NotFresh),
            }
        }
        Ok(destination)
    }
    /// The data directory the restore made, opened through the held parent
    /// without following a link and proven as its parent was: its identity
    /// (`st_dev`, `st_ino`), or why it is refused.
    pub(super) fn landed(&self, name: &str) -> Result<(u64, u64), RestoreDestinationRefusal> {
        use std::os::unix::fs::MetadataExt;
        let dir = self
            .open_landed()
            .map_err(|_| RestoreDestinationRefusal::Moved)?;
        let missing = self.missing_on(&dir, name);
        if !missing.is_empty() {
            return Err(RestoreDestinationRefusal::Unproven(missing));
        }
        let metadata = dir
            .metadata()
            .map_err(|_| RestoreDestinationRefusal::Moved)?;
        Ok((metadata.dev(), metadata.ino()))
    }
    /// The data directory's path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    /// The data directory at its name, opened through the held parent
    /// without following a link.
    pub(super) fn open_landed(&self) -> std::io::Result<std::fs::File> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        Ok(std::fs::File::from(rustix::fs::openat(
            &self.parent,
            self.leaf.as_os_str(),
            flags,
            Mode::empty(),
        )?))
    }
    /// Each facility `dir` lacks: an fscrypt v2 policy, and this dedicated
    /// non-root UID owning it with no group or other access, allocated to
    /// `name` at the data directory.
    fn missing_on(&self, dir: &std::fs::File, name: &str) -> Vec<&'static str> {
        use std::os::unix::fs::MetadataExt;
        let uid = rustix::process::geteuid().as_raw();
        let owned = dir.metadata().is_ok_and(|metadata| {
            uid != 0 && metadata.uid() == uid && metadata.mode() & 0o077 == 0
        });
        [
            (fscrypt_v2(dir), FSCRYPT_V2),
            (
                owned && uid_allocated(uid, name, &self.path) == Some(true),
                DEDICATED_UID,
            ),
        ]
        .into_iter()
        .filter_map(|(found, facility)| (!found).then_some(facility))
        .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conjunctive_probe_and_unique_uid_binding() {
        for (fscrypt, dedicated_uid, expected) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            assert_eq!(
                IsolationEvidence {
                    fscrypt,
                    dedicated_uid,
                    directory: None,
                }
                .admits(),
                expected
            );
        }
        let table = "1001\ta\t/var/vaults/a\n1002\tb\t/var/vaults/b".to_owned();
        assert!(uid_binding_matches(
            &table,
            1001,
            "a",
            Path::new("/var/vaults/a")
        ));
        assert!(!uid_binding_matches(
            &(table + "\n1001\tb\t/var/vaults/b"),
            1001,
            "a",
            Path::new("/var/vaults/a")
        ));
    }
    #[test]
    fn ordinary_directory_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!probe(dir.path(), "test").admits());
    }
}
