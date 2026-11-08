//! A blob body an ingress door hands over as a file (FIX 22074): the server
//! decodes a request's base64 member into a file before any writer opens,
//! and the engine reads the body from there, measured once, never as one
//! string or one buffer of the whole body.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Error, Result};
use crate::store::ASSET_INLINE_BODY_BYTES;

/// A blob body in a file its caller owns and does not change while the
/// engine holds it: its length and BLAKE3, read from its start to its end.
#[derive(Debug)]
pub struct BlobBodyFile<'f> {
    file: &'f File,
    len: u64,
    blake3: [u8; 32],
}

impl<'f> BlobBodyFile<'f> {
    /// Measures `file` from its start to its end: its length and BLAKE3.
    ///
    /// # Errors
    ///
    /// The file's read errors.
    pub fn measure(file: &'f File) -> Result<Self> {
        let mut reader = file;
        reader.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        let len = std::io::copy(&mut reader, &mut hasher)?;
        Ok(Self {
            file,
            len,
            blake3: *hasher.finalize().as_bytes(),
        })
    }

    /// The body's length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the body holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The body's BLAKE3.
    #[must_use]
    pub const fn blake3(&self) -> [u8; 32] {
        self.blake3
    }

    /// The file, read from its start.
    ///
    /// # Errors
    ///
    /// The file's seek error.
    pub(crate) fn reader(&self) -> Result<&'f File> {
        let mut reader = self.file;
        reader.seek(SeekFrom::Start(0))?;
        Ok(self.file)
    }

    /// The file read from its start, checked against the body it was
    /// measured as while it streams: a read past the measured length, or an
    /// end at another length or BLAKE3, fails before its reader takes the
    /// end, so a copy that publishes on a clean end never publishes other
    /// bytes under this body's digest.
    ///
    /// # Errors
    ///
    /// The file's seek error.
    pub(crate) fn checked_reader(&self) -> Result<CheckedBodyRead<'f>> {
        Ok(CheckedBodyRead {
            file: self.reader()?,
            hasher: blake3::Hasher::new(),
            read: 0,
            len: self.len,
            blake3: self.blake3,
        })
    }

    /// The whole body when it is no longer than the asset plane's inline
    /// size, which every door holds in memory as it does a slice; `None`
    /// for a longer one, which is only ever streamed.
    ///
    /// # Errors
    ///
    /// The file's read errors, and [`Error::InvariantViolation`] when the
    /// file no longer holds the body it was measured as.
    pub(crate) fn inline_bytes(&self) -> Result<Option<Vec<u8>>> {
        if self.len > ASSET_INLINE_BODY_BYTES {
            return Ok(None);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(self.len).unwrap_or_default());
        // One byte past the measured length shows a file that grew, without
        // reading what it grew by.
        self.reader()?
            .take(self.len.saturating_add(1))
            .read_to_end(&mut bytes)?;
        self.check(bytes.len() as u64, *blake3::hash(&bytes).as_bytes())?;
        Ok(Some(bytes))
    }

    /// Refuses facts that are not the ones this body was measured as: the
    /// file changed under the door that holds it.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] on a mismatch.
    pub(crate) fn check(&self, len: u64, blake3: [u8; 32]) -> Result<()> {
        if len == self.len && blake3 == self.blake3 {
            Ok(())
        } else {
            Err(Error::InvariantViolation(
                "a blob body file changed after it was measured",
            ))
        }
    }
}

/// [`BlobBodyFile::checked_reader`]'s reader.
pub(crate) struct CheckedBodyRead<'f> {
    file: &'f File,
    hasher: blake3::Hasher,
    read: u64,
    len: u64,
    blake3: [u8; 32],
}

impl Read for CheckedBodyRead<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read(out)?;
        if count == 0 {
            if self.read != self.len || *self.hasher.finalize().as_bytes() != self.blake3 {
                return Err(changed());
            }
            return Ok(0);
        }
        self.read = self.read.saturating_add(count as u64);
        if self.read > self.len {
            return Err(changed());
        }
        self.hasher.update(&out[..count]);
        Ok(count)
    }
}

/// A body file that is not the body it was measured as.
fn changed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "a blob body file changed after it was measured",
    )
}

/// The bytes a blob version or a waiting native output takes: a slice in
/// memory, or a body file an ingress door measured (FIX 22074).
#[derive(Clone, Copy)]
pub(crate) enum BlobContent<'a> {
    Bytes(&'a [u8]),
    File(&'a BlobBodyFile<'a>),
}

impl BlobContent<'_> {
    /// The content's length in bytes.
    pub(crate) fn len(self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File(file) => file.len(),
        }
    }

    /// Whether the content holds no bytes.
    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// The content's BLAKE3.
    pub(crate) fn blake3(self) -> [u8; 32] {
        match self {
            Self::Bytes(bytes) => *blake3::hash(bytes).as_bytes(),
            Self::File(file) => file.blake3(),
        }
    }
}
