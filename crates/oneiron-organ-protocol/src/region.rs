//! Read-only shared regions: how blob bytes cross without being copied.
//!
//! Linux: a memfd sealed against write, grow and shrink, so every holder sees
//! the same immutable bytes. Other Unix: a POSIX shared-memory object written
//! once, reopened read-only and unlinked; only the read-only descriptor ever
//! leaves this process.

use std::fs::File;
use std::io;
use std::ops::Deref;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use memmap2::{Mmap, MmapOptions};

/// An immutable region holding one blob's bytes.
#[derive(Debug)]
pub struct SharedRegion {
    fd: OwnedFd,
    len: u64,
}

impl SharedRegion {
    /// Copies `bytes` into a new region and makes it read-only for everyone.
    ///
    /// # Errors
    /// Fails if the OS refuses the region, or `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty blob rides inline",
            ));
        }
        Ok(Self {
            fd: create(bytes)?,
            len: bytes.len() as u64,
        })
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Gives up the region's descriptor, to send it away.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// The descriptor to pass to an organ.
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(target_os = "linux")]
fn create(bytes: &[u8]) -> io::Result<OwnedFd> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use std::io::Write;

    let fd = memfd_create(
        "oneiron-organ-region",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    let fd = OwnedFd::from(file);
    fcntl_add_seals(
        &fd,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(fd)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create(bytes: &[u8]) -> io::Result<OwnedFd> {
    let (name, rw) = open_fresh_name()?;
    let filled = fill_and_reopen(&name, rw, bytes);
    let unlinked = rustix::shm::unlink(name.as_str());
    let ro = filled?;
    unlinked?;
    Ok(ro)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn fill_and_reopen(name: &str, rw: OwnedFd, bytes: &[u8]) -> io::Result<OwnedFd> {
    use rustix::fs::{Mode, ftruncate};
    use rustix::shm;

    ftruncate(&rw, bytes.len() as u64)?;
    let file = File::from(rw);
    // SAFETY: the object was created a moment ago under an exclusive,
    // unpredictable name, so no other mapping or descriptor can resize or
    // write it while this mapping lives; the mapping and the writable
    // descriptor are dropped before the read-only descriptor is opened.
    let mut map = unsafe { MmapOptions::new().len(bytes.len()).map_mut(&file)? };
    map.copy_from_slice(bytes);
    drop(map);
    drop(file);
    Ok(shm::open(name, shm::OFlags::RDONLY, Mode::empty())?)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_fresh_name() -> io::Result<(String, OwnedFd)> {
    use rustix::fs::Mode;
    use rustix::shm;
    use std::time::{SystemTime, UNIX_EPOCH};

    let pid = std::process::id();
    for attempt in 0u32..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        // PSHMNAMLEN on macOS is 31 bytes, slash included.
        let name = format!("/onr.{pid:x}.{nanos:x}.{attempt:x}");
        match shm::open(
            name.as_str(),
            shm::OFlags::CREATE | shm::OFlags::EXCL | shm::OFlags::RDWR,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => return Ok((name, fd)),
            Err(rustix::io::Errno::EXIST) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no fresh shared-memory name",
    ))
}

/// A read-only view of a region, unmapped on drop.
#[derive(Debug)]
pub struct MappedRegion {
    map: Option<Mmap>,
}

impl MappedRegion {
    /// Maps `len` bytes of the region behind `fd`, read-only.
    ///
    /// On Linux the region must carry the write, grow and shrink seals, so
    /// the bytes cannot change or vanish under the mapping.
    ///
    /// # Errors
    /// Fails if the region is shorter than `len`, unsealed on Linux, or the
    /// OS refuses the mapping.
    pub fn map(fd: OwnedFd, len: u64) -> io::Result<Self> {
        let size = u64::try_from(rustix::fs::fstat(&fd)?.st_size).unwrap_or(0);
        if size < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "region is shorter than its handle says",
            ));
        }
        #[cfg(target_os = "linux")]
        require_seals(&fd)?;
        if len == 0 {
            return Ok(Self { map: None });
        }
        let len = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region too large"))?;
        let file = File::from(fd);
        // SAFETY: the region cannot change size or contents while mapped: on
        // Linux `require_seals` proved the write, grow and shrink seals; on
        // other Unix the creator holds no writable descriptor and the object
        // is sized once at creation. The mapping is read-only and private to
        // this value.
        let map = unsafe { MmapOptions::new().len(len).map(&file)? };
        Ok(Self { map: Some(map) })
    }
}

#[cfg(target_os = "linux")]
fn require_seals(fd: &OwnedFd) -> io::Result<()> {
    use rustix::fs::{SealFlags, fcntl_get_seals};
    let needed = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK;
    if fcntl_get_seals(fd)?.contains(needed) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "region is not sealed read-only",
        ))
    }
}

impl Deref for MappedRegion {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.map.as_deref().unwrap_or(&[])
    }
}
