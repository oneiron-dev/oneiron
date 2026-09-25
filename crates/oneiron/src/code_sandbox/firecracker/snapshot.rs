//! Descriptor-relative, no-symlink source snapshot for a foreign VM.

use super::refused;
use crate::{
    Result,
    code_sandbox::{SandboxFileWriteProposal, SandboxVirtualPath},
};
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

pub(super) fn files(root: &Path) -> Result<Vec<SandboxFileWriteProposal>> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| refused("source snapshot root unavailable"))?;
    let mut stack = vec![(root, String::new(), 0_usize)];
    let mut files = Vec::new();
    let mut directories = 0;
    let mut total = 0;
    while let Some((directory, prefix, depth)) = stack.pop() {
        // /proc/self/fd names the directory descriptor, not a mutable pathname.
        let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| refused("source snapshot directory unavailable"))?;
        for entry in entries {
            let entry = entry.map_err(|_| refused("source snapshot entry unavailable"))?;
            let name = entry.file_name();
            let leaf = name
                .to_str()
                .ok_or_else(|| refused("source filename is not UTF-8"))?;
            let path = if prefix.is_empty() {
                leaf.to_owned()
            } else {
                format!("{prefix}/{leaf}")
            };
            if path.len() > 4096 {
                return Err(refused("source snapshot path limit"));
            }
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
                directories += 1;
                if directories > 8192 || depth >= 64 {
                    return Err(refused("source snapshot directory limit"));
                }
                stack.push((file, path, depth + 1));
            } else if metadata.is_file() {
                if metadata.len() > 1024 * 1024 || files.len() >= 8192 {
                    return Err(refused("source snapshot file limit"));
                }
                let mut bytes = Vec::new();
                file.take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| refused("source snapshot read failed"))?;
                total += bytes.len();
                if bytes.len() > 1024 * 1024 || total > 16 * 1024 * 1024 {
                    return Err(refused("source snapshot byte limit"));
                }
                files.push(SandboxFileWriteProposal::new(
                    SandboxVirtualPath::try_new(format!("/mnt/workspace/{path}"))?,
                    bytes,
                ));
            } else {
                return Err(refused("source snapshot special file refused"));
            }
        }
    }
    files.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    Ok(files)
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
