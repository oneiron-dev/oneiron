//! Fail-closed Linux fscrypt and root-owned UID allocation probes.
use std::fs::File;
use std::path::Path;
/// The supervisor provisions this root-owned one-to-one allocation table.
/// Rows are `uid<TAB>vault-name<TAB>canonical-data-directory`.
#[cfg(target_os = "linux")]
const UID_REGISTRY: &str = "/etc/oneiron/vault-uids";
#[derive(Clone, Copy, Debug)]
pub(super) struct IsolationEvidence {
    pub fscrypt: bool,
    pub dedicated_uid: bool,
}
impl IsolationEvidence {
    pub(super) fn admits(self) -> bool {
        self.fscrypt && self.dedicated_uid
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
    let absent = IsolationEvidence {
        fscrypt: false,
        dedicated_uid: false,
    };
    let Ok(canonical) = path.canonicalize() else {
        return absent;
    };
    if canonical != path || !path.is_absolute() {
        return absent;
    }
    let Ok(dir) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
    else {
        return absent;
    };
    let Ok(metadata) = dir.metadata() else {
        return absent;
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
            .open(UID_REGISTRY)
            .ok()?;
        let meta = registry.metadata().ok()?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > 1_048_576
        {
            return None;
        }
        let mut text = String::new();
        registry.take(1_048_577).read_to_string(&mut text).ok()?;
        Some(uid_binding_matches(&text, uid, name, &canonical))
    };
    IsolationEvidence {
        fscrypt,
        dedicated_uid: uid != 0
            && metadata.uid() == uid
            && metadata.mode() & 0o077 == 0
            && allocated() == Some(true),
    }
}
#[cfg(not(target_os = "linux"))]
pub(super) fn probe(_path: &Path, _name: &str) -> IsolationEvidence {
    IsolationEvidence {
        fscrypt: false,
        dedicated_uid: false,
    }
}
#[cfg(any(target_os = "linux", test))]
fn uid_binding_matches(table: &str, uid: u32, name: &str, path: &Path) -> bool {
    let mut matched = 0;
    for line in table
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() != 3 {
            return false;
        }
        let Ok(row_uid) = parts[0].parse::<u32>() else {
            return false;
        };
        if row_uid == uid || parts[1] == name || Path::new(parts[2]) == path {
            if row_uid != uid || parts[1] != name || Path::new(parts[2]) != path {
                return false;
            }
            matched += 1;
        }
    }
    matched == 1
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
                    dedicated_uid
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

// C10: descriptor-bound probe trait over the writer-lease directory handle.
pub(super) trait IsolationProbe {
    fn fscrypt(&self, directory: &File) -> bool;
    fn dedicated_uid(&self, directory: &File, vault_name: &str) -> bool;
}

pub(super) struct NativeIsolation;

#[cfg(target_os = "linux")]
impl IsolationProbe for NativeIsolation {
    fn fscrypt(&self, directory: &File) -> bool {
        use std::os::fd::AsRawFd;
        // The vault's writer lease pins this same directory for LMDB open.
        // No pathname is reopened between the encryption and ownership checks.
        #[repr(C)]
        struct Policy {
            size: u64,
            policy: [u8; 24],
        }
        let mut policy = Policy {
            size: 24,
            policy: [0; 24],
        };
        // Linux UAPI FS_IOC_GET_ENCRYPTION_POLICY_EX = _IOWR('f', 22, __u8[9]).
        // SAFETY: fd is owned and live; Policy has the UAPI header and enough
        // space for both v1 and v2 policy payloads, with size initialized.
        let result = unsafe {
            libc::ioctl(
                directory.as_raw_fd(),
                0xc009_6616 as libc::c_ulong,
                &mut policy,
            )
        };
        result == 0 && matches!((policy.policy[0], policy.size), (0, 12) | (2, 24))
    }
    fn dedicated_uid(&self, directory: &File, vault_name: &str) -> bool {
        use std::{ffi::CString, os::unix::fs::MetadataExt};
        if !oneiron_vault_contract::valid_vault_name(vault_name) {
            return false;
        }
        let Ok(meta) = directory.metadata() else {
            return false;
        };
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return false;
        }
        let Ok(name) = CString::new(format!("oneiron-{vault_name}")) else {
            return false;
        };
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buf = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        // SAFETY: all writable buffers outlive this call. getpwnam_r writes a
        // passwd only on success, checked before assume_init below.
        let code = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if code != 0 || result.is_null() {
            return false;
        }
        // SAFETY: successful getpwnam_r initialized pwd. geteuid takes no args.
        let (pwd, uid) = unsafe { (pwd.assume_init(), libc::geteuid()) };
        uid != 0 && pwd.pw_uid == uid && meta.uid() == uid
    }
}

#[cfg(not(target_os = "linux"))]
impl IsolationProbe for NativeIsolation {
    fn fscrypt(&self, _: &File) -> bool {
        false
    }
    fn dedicated_uid(&self, _: &File, _: &str) -> bool {
        false
    }
}
