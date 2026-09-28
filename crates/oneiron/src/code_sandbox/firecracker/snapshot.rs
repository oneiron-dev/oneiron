//! Descriptor-relative, no-symlink source snapshot for a foreign VM.

use super::refused;
use crate::{
    Result,
    code_sandbox::{SandboxFileWriteProposal, SandboxVirtualPath},
};
use oneiron_sandbox_contract::{MAX_FILE_BYTES, WorkspacePath, WorkspaceShape};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

/// Snapshot bytes plus the checked tree they came from, empty directories
/// included, so proposals can be admitted against the same shape.
pub(super) struct Snapshot {
    pub files: Vec<SandboxFileWriteProposal>,
    pub shape: WorkspaceShape,
}

pub(super) fn files(root: &Path) -> Result<Snapshot> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| refused("source snapshot root unavailable"))?;
    let mut stack = vec![(root, String::new())];
    let mut files = Vec::new();
    let mut shape = WorkspaceShape::new();
    while let Some((directory, prefix)) = stack.pop() {
        // /proc/self/fd names the directory descriptor, not a mutable pathname.
        let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| refused("source snapshot directory unavailable"))?;
        for entry in entries {
            let entry = entry.map_err(|_| refused("source snapshot entry unavailable"))?;
            let name = entry.file_name();
            let leaf = name
                .to_str()
                .ok_or_else(|| refused("source filename is not UTF-8"))?;
            let relative = if prefix.is_empty() {
                leaf.to_owned()
            } else {
                format!("{prefix}/{leaf}")
            };
            let path =
                WorkspacePath::from_relative(&relative).map_err(|error| refused(error.reason()))?;
            let name =
                CString::new(name.as_bytes()).map_err(|_| refused("invalid source filename"))?;
            // SAFETY: directory is a live descriptor; name is NUL-terminated.
            // O_NOFOLLOW applies atomically to this one directory entry.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(refused("source snapshot symlink or inaccessible entry"));
            }
            // SAFETY: openat returned a new owned descriptor; File owns its close.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file
                .metadata()
                .map_err(|_| refused("source snapshot metadata unavailable"))?;
            if metadata.is_dir() {
                shape
                    .add_directory(&path)
                    .map_err(|error| refused(error.reason()))?;
                stack.push((file, relative));
            } else if metadata.is_file() {
                if metadata.len() > MAX_FILE_BYTES as u64 {
                    return Err(refused("source snapshot file limit"));
                }
                let mut bytes = Vec::new();
                file.take((MAX_FILE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| refused("source snapshot read failed"))?;
                shape
                    .add_file(&path, bytes.len())
                    .map_err(|error| refused(error.reason()))?;
                files.push(SandboxFileWriteProposal::new(
                    SandboxVirtualPath::try_new(path.as_str())?,
                    bytes,
                ));
            } else {
                return Err(refused("source snapshot special file refused"));
            }
        }
    }
    files.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    Ok(Snapshot { files, shape })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_refuses_symlinks_instead_of_reading_host_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret"), b"outside").expect("fixture");
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).expect("fixture");
        assert!(files(root.path()).is_err());
    }
}
