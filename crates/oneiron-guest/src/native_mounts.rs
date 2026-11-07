//! Native mount bytes are staged privately and verified before any execution.
use crate::{Error, Result};
use std::{
    ffi::{CStr, CString, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Take},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

struct DigestReader<R> {
    inner: Take<R>,
    digest: blake3::Hasher,
}
impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let len = self.inner.read(bytes)?;
        self.digest.update(&bytes[..len]);
        Ok(len)
    }
}

pub(crate) fn prepare(channel: &mut impl Read, bytes: u64, digest: [u8; 32]) -> Result<()> {
    let stage = Path::new("/tmp/.oneiron-native");
    fs::create_dir(stage)?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o700))?;
    let tree = stage.join("tree");
    fs::create_dir(&tree)?;
    let mut reader = DigestReader {
        inner: channel.take(bytes),
        digest: blake3::Hasher::new(),
    };
    let mut archive = tar::Archive::new(&mut reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.unpack(&tree)?;
    drop(archive);
    // Tar ends before its padding does. Consume and bind the entire declared
    // stream, leaving the next byte for the original native stdio protocol.
    std::io::copy(&mut reader, &mut std::io::sink())?;
    if reader.inner.limit() != 0 || reader.digest.finalize().as_bytes() != &digest {
        return Err(Error::Protocol("native mount digest"));
    }
    let destinations: Vec<Vec<u8>> =
        serde_json::from_reader(File::open(tree.join("destinations.json"))?)
            .map_err(|_| Error::Protocol("native mount destinations"))?;
    let mut mounts = Vec::new();
    for (index, destination) in destinations.into_iter().enumerate() {
        let destination = PathBuf::from(OsString::from_vec(destination));
        if !destination.is_absolute() {
            return Err(Error::Filesystem(
                "native mount destination must be absolute",
            ));
        }
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(tree.join(index.to_string()))?;
        mounts.push((source, destination));
    }
    if mounts.is_empty() {
        return Ok(());
    }
    prepare_root(stage)?;
    // Parent targets precede children, even if the caller listed a child first.
    // Nothing untrusted runs while these private copies are still writable.
    mounts.sort_by_key(|(_, destination)| destination.components().count());
    let mut installed = Vec::new();
    for (source, destination) in mounts {
        // The root is now the guest image's overlay. Absolute symlinks and
        // missing destination directories resolve only inside that root.
        fs::create_dir_all(&destination)?;
        let destination = fs::canonicalize(destination)?;
        let source = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
        mount(Some(&source), &destination, None, libc::MS_BIND, None)?;
        installed.push(destination);
    }
    // Finish nested mountpoint creation before making parents read-only.
    for destination in installed {
        mount(
            None,
            &destination,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
    }
    // Only caller-budgeted scratch and the original system mounts remain
    // writable. Neither the image nor the mounted source trees can be changed.
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
}

fn prepare_root(stage: &Path) -> Result<()> {
    let lower = stage.join("lower");
    let upper = stage.join("upper");
    let work = stage.join("work");
    let root = stage.join("root");
    for directory in [&lower, &upper, &work, &root] {
        fs::create_dir(directory)?;
    }
    // A non-recursive bind selects the immutable image, not the system/tmpfs
    // mounts which PID 1 has already installed over it.
    mount(Some(Path::new("/")), &lower, None, libc::MS_BIND, None)?;
    let data = CString::new(format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    ))
    .map_err(|_| Error::Filesystem("native overlay paths"))?;
    mount(
        Some(Path::new("overlay")),
        &root,
        Some(c"overlay"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&data),
    )?;
    for system in ["proc", "sys", "dev", "run", "tmp", "mnt"] {
        let destination = root.join(system);
        fs::create_dir_all(&destination)?;
        // /sys includes the existing pids cgroup mount. /tmp must NOT be
        // recursive: it contains this overlay's own backing directories.
        let flags = libc::MS_BIND
            | if matches!(system, "sys" | "dev" | "proc") {
                libc::MS_REC
            } else {
                0
            };
        mount(
            Some(&Path::new("/").join(system)),
            &destination,
            None,
            flags,
            None,
        )?;
    }
    let old = root.join(".oneiron-old-root");
    fs::create_dir(&old)?;
    let root = cstring(&root)?;
    let old = cstring(&old)?;
    // SAFETY: both directories belong to this private guest-only overlay;
    // PID 1 is the only process. The old root is detached before any child.
    if unsafe { libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: these are valid guest-root paths after the successful pivot.
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0
        || unsafe { libc::umount2(c"/.oneiron-old-root".as_ptr(), libc::MNT_DETACH) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    fs::remove_dir("/.oneiron-old-root")?;
    Ok(())
}

fn cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Filesystem("native mount path"))
}
fn mount(
    source: Option<&Path>,
    target: &Path,
    filesystem: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> Result<()> {
    let source = source.map(cstring).transpose()?;
    let target = cstring(target)?;
    // SAFETY: all optional strings and the target remain live for mount(2).
    if unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem.map_or(std::ptr::null(), CStr::as_ptr),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
