//! Descriptor-relative workspace access. No path resolution follows symlinks.

use crate::{
    Error, Result,
    protocol::{MAX_FILE, MAX_FILES, MAX_TOTAL, Snapshot},
};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

pub(crate) fn virtual_relative(path: &str) -> Result<&str> {
    let relative = path
        .strip_prefix("/mnt/workspace/")
        .ok_or(Error::Filesystem("not a workspace file"))?;
    if path.len() > 4096
        || relative.split('/').count() > 64
        || relative.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.len() > 255
                || part.contains(['\\', '\0'])
        })
    {
        return Err(Error::Filesystem("noncanonical or excessive path"));
    }
    Ok(relative)
}

pub(crate) fn validate_files(files: &Snapshot) -> Result<()> {
    if files.len() > MAX_FILES {
        return Err(Error::Filesystem("file count"));
    }
    let mut total = 0;
    let mut directories = BTreeSet::new();
    for (path, bytes) in files {
        let relative = virtual_relative(path)?;
        total += bytes.len();
        if bytes.len() > MAX_FILE || total > MAX_TOTAL {
            return Err(Error::Filesystem("file byte budget"));
        }
        let mut prefix = String::from("/mnt/workspace");
        let mut parts = relative.split('/').peekable();
        while let Some(part) = parts.next() {
            prefix.push('/');
            prefix.push_str(part);
            if parts.peek().is_some() {
                if files.contains_key(&prefix) {
                    return Err(Error::Filesystem("file/directory conflict"));
                }
                directories.insert(prefix.clone());
                if directories.len() > MAX_FILES {
                    return Err(Error::Filesystem("directory count"));
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct Workspace {
    root: File,
}

impl Workspace {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::Filesystem("workspace root must be absolute"));
        }
        let mut root = File::open("/")?;
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    root = open_directory(&root, &cstring(name.as_bytes())?)?;
                }
                _ => return Err(Error::Filesystem("workspace ancestor refused")),
            }
        }
        Ok(Self { root })
    }

    pub(crate) fn seed(&self, files: &Snapshot) -> Result<()> {
        validate_files(files)?;
        for (path, bytes) in files {
            self.write(path, bytes, true)?;
        }
        Ok(())
    }

    pub(crate) fn read(&self, path: &str) -> Result<Vec<u8>> {
        let (parent, name) = self.parent(path, false)?;
        read_regular(open_regular(&parent, &name, false, false)?)
    }

    pub(crate) fn apply(&self, proposals: &Snapshot) -> Result<()> {
        validate_files(proposals)?;
        // Refuse a merged tree that cannot later be enumerated within bounds.
        let mut merged = self.snapshot()?;
        merged.extend(proposals.clone());
        validate_files(&merged)?;
        for (path, bytes) in proposals {
            self.write(path, bytes, false)?;
        }
        Ok(())
    }

    fn write(&self, path: &str, bytes: &[u8], exclusive: bool) -> Result<()> {
        if bytes.len() > MAX_FILE {
            return Err(Error::Filesystem("write byte budget"));
        }
        let (parent, name) = self.parent(path, true)?;
        let mut file = open_regular(&parent, &name, true, exclusive)?;
        // Do not truncate until the opened descriptor itself passes the check.
        file.set_len(0)?;
        file.write_all(bytes)?;
        Ok(())
    }

    fn parent(&self, path: &str, create: bool) -> Result<(File, CString)> {
        let relative = virtual_relative(path)?;
        let mut directory = self.root.try_clone()?;
        let mut parts = relative.split('/').peekable();
        while let Some(part) = parts.next() {
            let name = cstring(part.as_bytes())?;
            if parts.peek().is_none() {
                return Ok((directory, name));
            }
            if create {
                // SAFETY: live directory descriptor and NUL-terminated leaf;
                // mkdirat cannot traverse the single leaf name.
                let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) };
                if result != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            directory = open_directory(&directory, &name)?;
        }
        Err(Error::Filesystem("missing filename"))
    }

    pub(crate) fn snapshot(&self) -> Result<Snapshot> {
        let mut files = Snapshot::new();
        let mut bytes = 0;
        self.walk(|file, path, directory| {
            if !directory {
                if files.len() >= MAX_FILES {
                    return Err(Error::Filesystem("snapshot file count"));
                }
                let contents = read_regular(file)?;
                bytes += contents.len();
                if bytes > MAX_TOTAL {
                    return Err(Error::Filesystem("snapshot aggregate bytes"));
                }
                files.insert(path, contents);
            }
            Ok(())
        })?;
        Ok(files)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_owner(&self, uid: u32, gid: u32) -> Result<()> {
        // Only used on the freshly seeded tree before any untrusted execution.
        self.walk(|file, _, _| {
            // SAFETY: the descriptor stays live; numeric uid/gid are supplied by
            // trusted PID 1, never by component input.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        })
    }

    fn walk(&self, mut visit: impl FnMut(File, String, bool) -> Result<()>) -> Result<()> {
        // Keep bounded path names, not one open fd per directory. A wide tree
        // must work under the child's small RLIMIT_NOFILE as well as a deep one.
        let mut stack = vec![String::from("/mnt/workspace")];
        let mut directories = 0;
        while let Some(prefix) = stack.pop() {
            let mut directory = self.root.try_clone()?;
            if prefix != "/mnt/workspace" {
                for part in virtual_relative(&prefix)?.split('/') {
                    directory = open_directory(&directory, &cstring(part.as_bytes())?)?;
                }
            }
            let mut entries = DirectoryEntries::new(&directory)?;
            while let Some(name) = entries.next()? {
                let leaf = name
                    .to_str()
                    .map_err(|_| Error::Filesystem("filename is not UTF-8"))?;
                let path = format!("{prefix}/{leaf}");
                virtual_relative(&path)?;
                let kind = entry_kind(&directory, &name)?;
                if kind == libc::S_IFDIR {
                    directories += 1;
                    if directories > MAX_FILES {
                        return Err(Error::Filesystem("snapshot directory count"));
                    }
                    stack.push(path);
                } else if kind == libc::S_IFREG {
                    visit(open_regular(&directory, &name, false, false)?, path, false)?;
                } else {
                    return Err(Error::Filesystem("symlink or special file"));
                }
            }
            visit(directory, prefix, true)?;
        }
        Ok(())
    }
}

fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| Error::Filesystem("NUL in filename"))
}

fn open_directory(parent: &File, name: &CStr) -> Result<File> {
    // SAFETY: parent is live and name NUL-terminated; every ancestor is opened
    // separately with O_NOFOLLOW, so no intermediate symlink can be traversed.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::Filesystem("directory inaccessible or symlink"));
    }
    // SAFETY: openat returned a new owned file descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn entry_kind(parent: &File, name: &CStr) -> Result<libc::mode_t> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: live parent/name and valid storage for stat. NOFOLLOW inspects
    // the leaf itself, including dangling symlinks and device nodes.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fstatat succeeded and initialized stat.
    Ok(unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT)
}

fn open_regular(parent: &File, name: &CStr, write: bool, exclusive: bool) -> Result<File> {
    match entry_kind(parent, name) {
        Ok(libc::S_IFREG) => {}
        Err(Error::Io(error)) if write && error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Error::Filesystem("not a regular file")),
    }
    let flags = if write {
        libc::O_WRONLY | libc::O_CREAT
    } else {
        libc::O_RDONLY
    } | if exclusive { libc::O_EXCL } else { 0 };
    // SAFETY: descriptor-relative single leaf; no truncation or symlink walk.
    // NONBLOCK also prevents blocking on a raced-in FIFO before the fstat check.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(Error::Filesystem("regular file open refused"));
    }
    // SAFETY: fd is newly owned after successful openat.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Error::Filesystem("special file or hard link"));
    }
    Ok(file)
}

fn read_regular(file: File) -> Result<Vec<u8>> {
    if file.metadata()?.len() > MAX_FILE as u64 {
        return Err(Error::Filesystem("read file size"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(Error::Filesystem("read byte budget"));
    }
    Ok(bytes)
}

struct DirectoryEntries(*mut libc::DIR);

impl DirectoryEntries {
    fn new(file: &File) -> Result<Self> {
        // A fresh open file description starts at offset zero on every walk.
        let directory = open_directory(file, c".")?;
        let fd = directory.into_raw_fd();
        // SAFETY: fd is owned and names a directory. fdopendir owns it on success.
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            // SAFETY: fdopendir failed, so ownership stayed with this function.
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(dir))
    }

    fn next(&mut self) -> Result<Option<CString>> {
        loop {
            // SAFETY: platform errno is thread-local; self owns a live DIR.
            // readdir's borrowed entry is copied before the next call.
            let entry = unsafe {
                *errno_pointer() = 0;
                libc::readdir(self.0)
            };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error.into())
                };
            }
            // SAFETY: successful readdir returns a NUL-terminated d_name valid
            // until the next call on this DIR; to_owned copies it now.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned();
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                return Ok(Some(name));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno cell.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno cell.
    unsafe { libc::__error() }
}

impl Drop for DirectoryEntries {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns a successfully opened DIR.
        unsafe { libc::closedir(self.0) };
    }
}
