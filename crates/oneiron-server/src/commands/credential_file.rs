//! A file holding a credential, readable by its owner alone.
//!
//! The mode bits do not say who can read a file on macOS: an extended ACL
//! entry grants access the mode does not show, and a new file takes its
//! directory's inheritable entries even when it is created 0600. So the file
//! is created with that inheritance refused, and a credential file that
//! carries an ACL entry is refused when it is read. A POSIX ACL elsewhere is
//! masked by the group bits, so mode 0600 already closes it.

use std::fs::File;
use std::path::{Path, PathBuf};

/// Why a credential file is not admitted.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialFileError {
    /// The mode lets the group or other users in.
    #[error("{} can be read by other users (mode {mode:o}); run `chmod 600` on it", path.display())]
    OpenMode { path: PathBuf, mode: u32 },
    /// An ACL entry can grant what the mode does not show. Only macOS keeps
    /// entries the mode does not mask.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[error(
        "{} has an access control list, which can let other users read it; run `chmod -N` on it",
        path.display()
    )]
    ExtendedAcl { path: PathBuf },
    /// Who can read it could not be read.
    #[error("check who can read {}: {source}", path.display())]
    Unchecked {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Creates `path`: a new file, never one that already exists (someone else
/// may hold it open), mode 0600 and with no ACL entry from its directory. A
/// file that is not admitted all the same is removed, not handed back.
pub(crate) fn create(path: &Path) -> anyhow::Result<File> {
    let file =
        create_new(path).map_err(|error| anyhow::anyhow!("create {}: {error}", path.display()))?;
    if let Err(refused) = admit(path, &file) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(refused.into());
    }
    Ok(file)
}

/// Admits an open credential file only when no one but its owner can read it.
pub(crate) fn admit(path: &Path, file: &File) -> Result<(), CredentialFileError> {
    let unchecked = |source| CredentialFileError::Unchecked {
        path: path.to_owned(),
        source,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata().map_err(unchecked)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CredentialFileError::OpenMode {
                path: path.to_owned(),
                mode: mode & 0o777,
            });
        }
    }
    #[cfg(target_os = "macos")]
    if macos::has_acl_entry(file).map_err(unchecked)? {
        return Err(CredentialFileError::ExtendedAcl {
            path: path.to_owned(),
        });
    }
    #[cfg(not(unix))]
    let _ = (file, unchecked);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn create_new(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(target_os = "macos")]
fn create_new(path: &Path) -> std::io::Result<File> {
    macos::create_without_inherited_acl(path)
}

/// The libSystem ACL calls, as `<sys/acl.h>` and `<sys/fcntl.h>` declare them.
#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, c_char, c_int, c_uint, c_void};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// `acl_type_t`: the one ACL type macOS keeps.
    const ACL_TYPE_EXTENDED: c_uint = 0x0000_0100;
    /// `acl_entry_id_t`.
    const ACL_FIRST_ENTRY: c_int = 0;
    /// `acl_flag_t`: an ACL given at creation that takes nothing from the
    /// directory.
    const ACL_FLAG_NO_INHERIT: c_uint = 1 << 17;
    /// `filesec_property_t`.
    const FILESEC_MODE: c_uint = 4;
    const FILESEC_ACL: c_uint = 5;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_free(obj: *mut c_void) -> c_int;
        fn acl_get_fd_np(fd: c_int, kind: c_uint) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_flagset_np(obj: *mut c_void, flagset: *mut *mut c_void) -> c_int;
        fn acl_add_flag_np(flagset: *mut c_void, flag: c_uint) -> c_int;
        fn acl_set_flagset_np(obj: *mut c_void, flagset: *mut c_void) -> c_int;
        fn filesec_init() -> *mut c_void;
        fn filesec_free(security: *mut c_void);
        fn filesec_set_property(
            security: *mut c_void,
            property: c_uint,
            value: *const c_void,
        ) -> c_int;
        fn openx_np(path: *const c_char, flags: c_int, security: *mut c_void) -> c_int;
    }

    /// An ACL the library allocated, freed once.
    struct Acl(*mut c_void);

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: a non-null ACL from `acl_init` or `acl_get_fd_np`,
            // owned by this guard and freed nowhere else.
            unsafe { acl_free(self.0) };
        }
    }

    /// A file security descriptor the library allocated, freed once.
    struct Filesec(*mut c_void);

    impl Drop for Filesec {
        fn drop(&mut self) {
            // SAFETY: a non-null descriptor from `filesec_init`, owned by
            // this guard and freed nowhere else.
            unsafe { filesec_free(self.0) };
        }
    }

    /// `open(O_CREAT | O_EXCL)` at mode 0600 with an empty ACL that refuses
    /// inheritance, so the kernel gives the new file no entry from its
    /// directory: there is no moment at which another user could open it.
    pub(super) fn create_without_inherited_acl(path: &Path) -> io::Result<File> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path holds a NUL"))?;
        // SAFETY: takes a count, returns an owned ACL or null.
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let acl = Acl(acl);
        let mut flags = std::ptr::null_mut();
        // SAFETY: `acl.0` is a live ACL and `flags` a valid out-pointer; on
        // success `flags` is that ACL's own flag set, used while it lives.
        let flagged = unsafe {
            acl_get_flagset_np(acl.0, &mut flags) == 0
                && acl_add_flag_np(flags, ACL_FLAG_NO_INHERIT) == 0
                && acl_set_flagset_np(acl.0, flags) == 0
        };
        if !flagged {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: takes nothing, returns an owned descriptor or null.
        let security = unsafe { filesec_init() };
        if security.is_null() {
            return Err(io::Error::last_os_error());
        }
        let security = Filesec(security);
        let mode: libc::mode_t = 0o600;
        // SAFETY: `security` is live; each value points at the type its
        // property reads (`mode_t`, `acl_t`), which the call copies.
        let described = unsafe {
            filesec_set_property(security.0, FILESEC_MODE, (&raw const mode).cast()) == 0
                && filesec_set_property(security.0, FILESEC_ACL, (&raw const acl.0).cast()) == 0
        };
        if !described {
            return Err(io::Error::last_os_error());
        }
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
        // SAFETY: `path` is NUL-terminated and `security` is live for the call.
        let fd = unsafe { openx_np(path.as_ptr(), flags, security.0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was opened by the call above and nothing else owns it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Whether the open file carries an extended ACL entry.
    pub(super) fn has_acl_entry(file: &File) -> io::Result<bool> {
        // SAFETY: a live descriptor; returns an owned ACL, or null and errno.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            // No ACL, or a filesystem that keeps none.
            return match error.raw_os_error() {
                Some(libc::ENOENT | libc::ENOTSUP | libc::EOPNOTSUPP) => Ok(false),
                _ => Err(error),
            };
        }
        let acl = Acl(acl);
        let mut entry = std::ptr::null_mut();
        // SAFETY: a live ACL and a valid out-pointer; 0 means it has a first
        // entry.
        Ok(unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) } == 0)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::process::Command;

    /// `chmod +a`, the owner's own tool for adding an ACL entry.
    fn add_acl_entry(path: &Path, entry: &str) {
        let added = Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .status()
            .expect("run chmod +a");
        assert!(added.success(), "chmod +a {entry} on {}", path.display());
    }

    /// Sol F5 (#1346): a 0600 file created in a directory with an inheritable
    /// ACL entry was readable by that entry's users. The credential file
    /// takes no entry from its directory, and one that has an entry is
    /// refused with a typed error.
    #[test]
    fn a_credential_file_takes_no_inherited_acl_and_one_with_an_acl_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        add_acl_entry(dir.path(), "everyone allow read,file_inherit");

        // The directory passes its entry on to a plain 0600 file.
        let plain = dir.path().join("plain");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&plain)
                .unwrap();
            assert!(
                macos::has_acl_entry(&file).unwrap(),
                "the directory's entry should reach a plain file"
            );
            assert!(matches!(
                admit(&plain, &file),
                Err(CredentialFileError::ExtendedAcl { .. })
            ));
        }

        // Not to the credential file.
        let credential = dir.path().join("agent.cred");
        let file = create(&credential).expect("create the credential file");
        assert!(!macos::has_acl_entry(&file).unwrap());
        drop(file);
        let file = File::open(&credential).unwrap();
        admit(&credential, &file).expect("an owner-only credential file is admitted");

        // An entry added later is refused at admission.
        add_acl_entry(&credential, "everyone allow read");
        let file = File::open(&credential).unwrap();
        let refused = admit(&credential, &file).unwrap_err();
        assert!(
            matches!(refused, CredentialFileError::ExtendedAcl { .. }),
            "{refused}"
        );
    }
}
