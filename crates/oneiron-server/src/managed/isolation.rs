//! Fail-closed operating-system evidence for real managed tenants.

use std::path::Path;

pub(super) trait IsolationProbe {
    fn fscrypt(&self, path: &Path) -> bool;
    fn dedicated_uid(&self, path: &Path, vault_name: &str) -> bool;
}

pub(super) struct NativeIsolation;

#[cfg(target_os = "linux")]
impl IsolationProbe for NativeIsolation {
    fn fscrypt(&self, path: &Path) -> bool {
        use std::{
            fs::OpenOptions,
            os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        };
        // Refuse links and require an existing directory. The kernel, not a
        // marker file or environment variable, answers whether it is encrypted.
        let Ok(dir) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
        else {
            return false;
        };
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
        let result =
            unsafe { libc::ioctl(dir.as_raw_fd(), 0xc009_6616 as libc::c_ulong, &mut policy) };
        result == 0 && matches!((policy.policy[0], policy.size), (0, 12) | (2, 24))
    }
    fn dedicated_uid(&self, path: &Path, vault_name: &str) -> bool {
        use std::{ffi::CString, os::unix::fs::MetadataExt};
        if !oneiron_vault_contract::valid_vault_name(vault_name) {
            return false;
        }
        let Ok(meta) = std::fs::symlink_metadata(path) else {
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
    fn fscrypt(&self, _: &Path) -> bool {
        false
    }
    fn dedicated_uid(&self, _: &Path, _: &str) -> bool {
        false
    }
}
