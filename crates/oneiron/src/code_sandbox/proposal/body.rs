//! A proposed file's bytes, spooled to an anonymous host temp file as they
//! arrive. A foreign guest streams a file of any size in frames; the host
//! never holds it whole, and review reads only the ranges it needs.

use crate::{Error, Result};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

/// The settled bytes of one proposed file: their length, their BLAKE3 digest
/// and the unnamed temp file that holds them. Clones share the one file,
/// which is removed when the last clone drops.
#[derive(Clone)]
pub struct SandboxProposalBody {
    spooled: Arc<Spooled>,
}

struct Spooled {
    file: Mutex<File>,
    len: u64,
    digest: [u8; 32],
}

impl SandboxProposalBody {
    /// Starts a body that frames are appended to, in order.
    pub fn spool() -> Result<SandboxProposalBodyWriter> {
        Ok(SandboxProposalBodyWriter {
            file: tempfile::tempfile()?,
            len: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// A body holding `bytes`, spooled like a streamed one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut writer = Self::spool()?;
        writer.append(bytes)?;
        writer.finish()
    }

    /// Spools everything `source` yields, one bounded buffer at a time.
    pub fn copy_from(source: &mut impl Read) -> Result<Self> {
        let mut writer = Self::spool()?;
        let mut frame = vec![0; READ_FRAME];
        loop {
            let read = match source.read(&mut frame) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            writer.append(&frame[..read])?;
        }
        writer.finish()
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.spooled.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spooled.len == 0
    }

    /// BLAKE3 of the whole body, computed as it was spooled.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.spooled.digest
    }

    /// Whether the body is exactly `bytes`, decided by length and digest.
    #[must_use]
    pub fn is(&self, bytes: &[u8]) -> bool {
        self.spooled.len == bytes.len() as u64
            && self.spooled.digest == *blake3::hash(bytes).as_bytes()
    }

    /// The `len` bytes at `offset`. A range past the end is refused.
    pub fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.spooled.len)
        {
            return Err(Error::InvalidClaimBody("proposal body range out of bounds"));
        }
        let mut bytes = vec![0; len];
        let mut file = self
            .spooled
            .file
            .lock()
            .map_err(|_| Error::InvalidClaimBody("proposal body poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Reads the body from its start, one call's buffer at a time.
    #[must_use]
    pub fn reader(&self) -> SandboxProposalBodyReader {
        SandboxProposalBodyReader {
            body: self.clone(),
            at: 0,
        }
    }
}

impl std::fmt::Debug for SandboxProposalBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxProposalBody")
            .field("len", &self.spooled.len)
            .field(
                "digest",
                &blake3::Hash::from_bytes(self.spooled.digest).to_hex(),
            )
            .finish()
    }
}

/// Two bodies are equal when their bytes are: same length, same digest.
impl PartialEq for SandboxProposalBody {
    fn eq(&self, other: &Self) -> bool {
        self.spooled.len == other.spooled.len && self.spooled.digest == other.spooled.digest
    }
}
impl Eq for SandboxProposalBody {}

/// One host buffer of a spool copy or a body read; never a size bound.
const READ_FRAME: usize = 1024 * 1024;

/// A body still being written. Nothing reads it until [`Self::finish`].
pub struct SandboxProposalBodyWriter {
    file: File,
    len: u64,
    hasher: blake3::Hasher,
}

impl SandboxProposalBodyWriter {
    /// Appends one frame.
    pub fn append(&mut self, frame: &[u8]) -> Result<()> {
        self.file.write_all(frame)?;
        self.hasher.update(frame);
        self.len = self
            .len
            .checked_add(frame.len() as u64)
            .ok_or(Error::InvalidClaimBody("proposal body length overflow"))?;
        Ok(())
    }

    /// Bytes appended so far.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Settles the body: its length and digest are fixed from here on.
    pub fn finish(mut self) -> Result<SandboxProposalBody> {
        self.file.flush()?;
        Ok(SandboxProposalBody {
            spooled: Arc::new(Spooled {
                file: Mutex::new(self.file),
                len: self.len,
                digest: *self.hasher.finalize().as_bytes(),
            }),
        })
    }
}

/// A sequential reader over one body.
pub struct SandboxProposalBodyReader {
    body: SandboxProposalBody,
    at: u64,
}

impl Read for SandboxProposalBodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let left = self.body.len() - self.at;
        let take = usize::try_from(left).map_or(buffer.len(), |left| left.min(buffer.len()));
        if take == 0 {
            return Ok(0);
        }
        let mut file = self
            .body
            .spooled
            .file
            .lock()
            .map_err(|_| std::io::Error::other("proposal body poisoned"))?;
        file.seek(SeekFrom::Start(self.at))?;
        file.read_exact(&mut buffer[..take])?;
        self.at += take as u64;
        Ok(take)
    }
}
