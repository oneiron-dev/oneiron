//! A native call's regions. Its input region: the conversation's bytes
//! copied once into an immutable shared region
//! (`oneiron_organ_protocol::SharedRegion`: a memfd sealed against write,
//! grow and shrink on Linux, a read-only POSIX shared-memory object
//! elsewhere), whose one descriptor rides on the call's `generate` frame.
//!
//! The host's descriptor lives until the worker has answered `accepted` or
//! `refused`; the copy the kernel passed is the worker's to map, read and
//! close. Nothing here maps a region, and nothing caps its size.
//!
//! A snapshot region (codec v1.2): the bytes of one `session.export`, in a
//! region the worker sealed and passed on its answer's frame, taken only
//! once its descriptor is shown one whole immutable region of exactly the
//! length the answer names; or bytes made into a region here, to import.
//! The descriptor this side received is its own: dropping the region
//! closes it.
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;

use oneiron::llm::{RegionDescriptor, SNAPSHOT_ENCODING};
use oneiron_organ_protocol::SharedRegion;
use sha2::{Digest, Sha256};

use super::wire::CHAT_JSON;

/// How much one read of a snapshot region takes: a read size, never a cap.
const READ_CHUNK: usize = 1 << 20;

/// A region on its way out: its descriptor, its length and its encoding,
/// as its description names them.
pub(super) struct Outbound<'a> {
    pub(super) fd: BorrowedFd<'a>,
    pub(super) len: u64,
    pub(super) encoding: &'static str,
}

/// One call's input, ready to send.
pub(super) struct InputRegion {
    region: SharedRegion,
}

impl InputRegion {
    /// A region holding `bytes`, which are never empty: a conversation is
    /// at least `{}`.
    pub(super) fn new(bytes: &[u8]) -> io::Result<Self> {
        Ok(Self {
            region: SharedRegion::from_bytes(bytes)?,
        })
    }

    /// The region's length, as its description names it.
    pub(super) fn len(&self) -> u64 {
        self.region.len()
    }

    /// The descriptor to pass.
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.region.fd()
    }

    /// The region as an op's `chat_json` input.
    pub(super) fn outbound(&self) -> Outbound<'_> {
        Outbound {
            fd: self.fd(),
            len: self.len(),
            encoding: CHAT_JSON,
        }
    }
}

/// One snapshot in an immutable region this side holds.
pub(in crate::models) struct SnapshotRegion {
    file: File,
    len: u64,
}

impl SnapshotRegion {
    /// A region holding `bytes`, sealed as an input region is, to import.
    #[expect(
        dead_code,
        reason = "the R3 restore path is its caller (worker_host/session); it is not built yet"
    )]
    pub(in crate::models) fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let region = SharedRegion::from_bytes(bytes)?;
        let len = region.len();
        Ok(Self {
            file: File::from(region.into_fd()),
            len,
        })
    }

    /// The region the worker passed as `fd` under `descriptor`, taken only
    /// when it is one whole `snapshot_v1` region at descriptor 0 of exactly
    /// `length` bytes, regular, and immutable: sealed against write, grow
    /// and shrink on Linux, open read-only elsewhere. Otherwise the
    /// descriptor is closed here.
    pub(super) fn received(
        fd: OwnedFd,
        descriptor: &RegionDescriptor,
        length: u64,
    ) -> io::Result<Self> {
        if descriptor.fd_index != 0
            || descriptor.offset != 0
            || descriptor.encoding != SNAPSHOT_ENCODING
            || descriptor.length != length
            || length == 0
        {
            return Err(invalid(
                "the output is not one whole snapshot region at descriptor 0",
            ));
        }
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(invalid("the output is not a memory region"));
        }
        if metadata.len() != length {
            return Err(invalid("the output region's size is not the snapshot's"));
        }
        immutable(&file)?;
        Ok(Self { file, len: length })
    }

    /// The snapshot's length.
    pub(in crate::models) fn len(&self) -> u64 {
        self.len
    }

    /// The snapshot's bytes, read whole.
    #[expect(
        dead_code,
        reason = "the R3 park path is its caller (worker_host/session); it is not built yet"
    )]
    pub(in crate::models) fn read(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len).map_err(|_| invalid("the snapshot is too long"))?;
        let mut bytes = vec![0_u8; len];
        self.file.read_exact_at(&mut bytes, 0)?;
        Ok(bytes)
    }

    /// The SHA-256 of the snapshot's bytes, read a chunk at a time.
    pub(super) fn sha256(&self) -> io::Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut chunk = vec![0_u8; READ_CHUNK];
        let mut offset = 0_u64;
        while offset < self.len {
            let left = usize::try_from(self.len - offset).unwrap_or(usize::MAX);
            let piece = &mut chunk[..left.min(READ_CHUNK)];
            self.file.read_exact_at(piece, offset)?;
            hasher.update(&*piece);
            offset += u64::try_from(piece.len()).unwrap_or(u64::MAX);
        }
        Ok(hasher.finalize().into())
    }

    /// The region as an op's `snapshot_v1` input.
    pub(super) fn outbound(&self) -> Outbound<'_> {
        Outbound {
            fd: self.file.as_fd(),
            len: self.len,
            encoding: SNAPSHOT_ENCODING,
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Linux: the region is sealed against write, grow and shrink, so every
/// holder sees the same bytes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn immutable(file: &File) -> io::Result<()> {
    use rustix::fs::{SealFlags, fcntl_get_seals};

    let needed = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK;
    if fcntl_get_seals(file)?.contains(needed) {
        Ok(())
    } else {
        Err(invalid("the output region is not sealed read-only"))
    }
}

/// Elsewhere: the descriptor passed is open read-only.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn immutable(file: &File) -> io::Result<()> {
    use rustix::fs::{OFlags, fcntl_getfl};

    if (fcntl_getfl(file)? & OFlags::RWMODE) == OFlags::RDONLY {
        Ok(())
    } else {
        Err(invalid("the output region is not read-only"))
    }
}
