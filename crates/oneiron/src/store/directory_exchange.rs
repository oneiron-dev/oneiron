//! Descriptor-held entries for the atomic exchange in ARCH-0038's restore path.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, open, statat};

use super::root_directory::FileIdentity;
use crate::{Error, Result};

/// A name inside a parent directory held open since the restore's checks.
pub struct HeldEntry {
    parent: OwnedFd,
    name: CString,
}

impl HeldEntry {
    /// Holds the parent of `path` and keeps its final component for the exchange.
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| Error::InvalidConfig("an exchange path needs a parent".into()))?;
        let name = path
            .file_name()
            .ok_or_else(|| Error::InvalidConfig("an exchange path needs a name".into()))?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| Error::InvalidConfig("an exchange name contains a NUL byte".into()))?;
        let parent = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        Ok(Self { parent, name })
    }

    /// The directory descriptor that anchors this entry.
    pub fn parent(&self) -> BorrowedFd<'_> {
        self.parent.as_fd()
    }

    /// The final component, interpreted only inside the held parent.
    pub fn name(&self) -> &CStr {
        &self.name
    }

    /// The directory currently under this name, without following a final link.
    pub(in crate::store) fn identity(&self) -> Result<Option<FileIdentity>> {
        let stat = match statat(self.parent(), self.name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Ok(None);
        }
        Ok(Some(FileIdentity {
            dev: identity_component(stat.st_dev)?,
            ino: identity_component(stat.st_ino)?,
        }))
    }

    /// Persists a rename in the parent the exchange actually used.
    pub(in crate::store) fn sync_parent(&self) -> std::io::Result<()> {
        Ok(rustix::fs::fsync(self.parent())?)
    }
}

fn identity_component(value: impl TryInto<u64>) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| Error::InvariantViolation("directory identity exceeds u64"))
}

/// Exchanges the checked entries inside their held parents, never by reopening paths.
pub fn exchange_held(a: &HeldEntry, b: &HeldEntry) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(rustix::fs::renameat_with(
            a.parent(),
            a.name(),
            b.parent(),
            b.name(),
            rustix::fs::RenameFlags::EXCHANGE,
        )?)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (a, b);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic directory exchange is unsupported",
        ))
    }
}
