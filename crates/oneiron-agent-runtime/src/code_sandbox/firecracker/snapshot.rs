//! Descriptor-relative, no-symlink source snapshot for a foreign VM.

use super::refused;
use crate::{
    Result,
    code_sandbox::{ProposalSpoolFloor, SandboxProposalBody, SandboxVirtualPath},
    engine_executor::StepCancellation,
};
use oneiron_sandbox_contract::{MAX_CHUNK_BYTES, WorkspacePath, WorkspaceShape};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
    time::Instant,
};

/// Snapshot bytes plus the checked tree they came from, empty directories
/// included, so proposals can be admitted against the same shape.
pub(super) struct Snapshot {
    pub files: Vec<SnapshotFile>,
    pub shape: WorkspaceShape,
}

/// One source file as the guest is seeded with it.
pub(super) struct SnapshotFile {
    pub path: SandboxVirtualPath,
    pub body: SandboxProposalBody,
}

pub(super) fn files(
    root: &Path,
    spool: Option<&dyn ProposalSpoolFloor>,
    cancel: &StepCancellation,
    deadline: Instant,
) -> Result<Snapshot> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| refused("source snapshot root unavailable"))?;
    let mut stack = vec![(root, String::new())];
    // All source files share one spool descriptor, including wide trees.
    let mut writer = match spool {
        Some(floor) => SandboxProposalBody::spool_floored(floor)?,
        None => SandboxProposalBody::spool()?,
    };
    let mut frame = vec![0; MAX_CHUNK_BYTES];
    let mut ranges = Vec::new();
    let mut shape = WorkspaceShape::new();
    while let Some((directory, prefix)) = stack.pop() {
        checkpoint(cancel, deadline)?;
        // /proc/self/fd names the directory descriptor, not a mutable pathname.
        let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| refused("source snapshot directory unavailable"))?;
        for entry in entries {
            checkpoint(cancel, deadline)?;
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
                let start = writer.len();
                let mut hasher = blake3::Hasher::new();
                let mut file = file;
                loop {
                    checkpoint(cancel, deadline)?;
                    let read = match file.read(&mut frame) {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err(refused("source snapshot read failed")),
                    };
                    writer.append(&frame[..read])?;
                    hasher.update(&frame[..read]);
                }
                let len = writer.len() - start;
                shape
                    .add_file(
                        &path,
                        usize::try_from(len)
                            .map_err(|_| refused("source snapshot length overflow"))?,
                    )
                    .map_err(|error| refused(error.reason()))?;
                ranges.push((
                    SandboxVirtualPath::try_new(path.as_str())?,
                    start,
                    len,
                    *hasher.finalize().as_bytes(),
                ));
            } else {
                return Err(refused("source snapshot special file refused"));
            }
        }
    }
    let body = writer.finish()?;
    let mut files = Vec::with_capacity(ranges.len());
    for (path, start, len, digest) in ranges {
        files.push(SnapshotFile {
            path,
            body: body.slice_with_digest(start, len, digest)?,
        });
    }
    files.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    Ok(Snapshot { files, shape })
}

fn checkpoint(cancel: &StepCancellation, deadline: Instant) -> Result<()> {
    cancel.check()?;
    if Instant::now() >= deadline {
        return Err(refused("source snapshot deadline exceeded"));
    }
    Ok(())
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
