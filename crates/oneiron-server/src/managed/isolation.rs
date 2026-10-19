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
#[cfg(target_os = "linux")]
pub(super) fn probe(path: &Path, name: &str) -> IsolationEvidence {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    // FS_IOC_GET_ENCRYPTION_POLICY_EX, linux/fscrypt.h. The kernel fills
    // policy_size and one of the v1 (12-byte) or v2 (24-byte) policy unions.
    #[repr(C)]
    struct Policy {
        size: u64,
        bytes: [u8; 24],
    }
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
    let mut policy = Policy {
        size: 24,
        bytes: [0; 24],
    };
    // The UAPI deliberately encodes __u8[9] (size + version), not sizeof(Policy).
    // Its request number stays 0xc0096616 even though this buffer is 32 bytes.
    // SAFETY: live directory fd; correctly sized/aligned writable UAPI buffer.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), 0xc0096616 as libc::c_ulong, &mut policy) };
    let fscrypt = rc == 0 && matches!((policy.bytes[0], policy.size), (0, 12) | (2, 24));
    // SAFETY: geteuid has no pointer arguments or memory effects.
    let uid = unsafe { libc::geteuid() };
    let allocated = || -> Option<bool> {
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
        Some(uid_binding_matches(&text, uid, name, &canonical))
    };
    IsolationEvidence {
        fscrypt,
        dedicated_uid: uid != 0
            && metadata.uid() == uid
            && metadata.mode() & 0o077 == 0
            && allocated() == Some(true),
        directory: Some(dir),
    }
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
