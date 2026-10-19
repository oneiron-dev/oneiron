//! An open body file, whichever form it rests in: what every reader of a
//! body file gets in place of a `File` (FIX 5348).

use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;

use zeroize::Zeroizing;

use super::frames::{
    FileKey, Layout, SealedStream, check_terminal, checked_layout, chunk_of, read_chunk,
};
use crate::error::{Error, Result};

/// One body file held open for reading: plain, or an envelope with its
/// opened key, held until the file closes. A range read returns only bytes
/// it read and, for an envelope, authenticated; a sequential read goes from
/// the start.
pub(crate) struct BodyFile {
    inner: Inner,
    len: u64,
    /// Where a sequential read of an envelope is, and the chunk it holds.
    at: u64,
    chunk: Option<(u64, Zeroizing<Vec<u8>>)>,
}

enum Inner {
    Plain(File),
    Sealed {
        file: File,
        key: Arc<FileKey>,
        layout: Layout,
        digest: [u8; 32],
    },
}

impl BodyFile {
    /// The plain body file `file`, `len` bytes long.
    pub(crate) fn plain(file: File, len: u64) -> Self {
        Self {
            inner: Inner::Plain(file),
            len,
            at: 0,
            chunk: None,
        }
    }

    /// The envelope `file` of the body `digest`, `len` bytes long, sealed
    /// under `key`: its head, its whole length and its terminal record are
    /// checked before it is handed out.
    pub(super) fn sealed(
        file: File,
        key: Arc<FileKey>,
        digest: &[u8; 32],
        len: u64,
    ) -> Result<Self> {
        let layout = checked_layout(&file, &key, len)?;
        check_terminal(&file, &key, &layout, digest)?;
        Ok(Self {
            inner: Inner::Sealed {
                file,
                key,
                layout,
                digest: *digest,
            },
            len,
            at: 0,
            chunk: None,
        })
    }

    /// The file's length on disk: the body's, or its envelope's.
    ///
    /// # Errors
    ///
    /// [`Error::ArithmeticOverflow`] past `u64`.
    pub(crate) fn stored_len(&self) -> Result<u64> {
        match &self.inner {
            Inner::Plain(_) => Ok(self.len),
            Inner::Sealed { layout, .. } => layout.physical(),
        }
    }

    /// The file's bytes as they rest, from the start: a plain body's own,
    /// or an envelope's ciphertext, each envelope authenticated as it
    /// passes.
    pub(crate) fn into_stored(self) -> Box<dyn Read + Send> {
        match self.inner {
            Inner::Plain(file) => Box::new(file),
            Inner::Sealed {
                file, key, digest, ..
            } => Box::new(SealedStream::ciphertext(file, key, digest, self.len)),
        }
    }

    /// The envelope's file, key and body digest, for a copy of its
    /// ciphertext; a plain body's file as the error.
    pub(super) fn into_sealed(self) -> std::result::Result<(File, Arc<FileKey>, [u8; 32]), File> {
        match self.inner {
            Inner::Plain(file) => Err(file),
            Inner::Sealed {
                file, key, digest, ..
            } => Ok((file, key, digest)),
        }
    }

    /// `len` bytes of the body from `offset`, which must lie within it. An
    /// envelope's chunks are each authenticated before a byte of them is
    /// returned; no other chunk is read.
    ///
    /// # Errors
    ///
    /// A range past the body's end, a frame that does not open, and
    /// filesystem errors.
    pub(crate) fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let (file, key, layout) = match &self.inner {
            Inner::Plain(file) => return crate::store::read_body_range(file, offset, len),
            Inner::Sealed {
                file, key, layout, ..
            } => (file, key, layout),
        };
        let end = offset
            .checked_add(len as u64)
            .filter(|end| *end <= self.len)
            .ok_or_else(|| Error::from(io::Error::from(io::ErrorKind::UnexpectedEof)))?;
        let mut out = Vec::with_capacity(len);
        let mut at = offset;
        while at < end {
            let (index, from) = chunk_of(at);
            let chunk = read_chunk(file, key, layout, index)?;
            let from =
                usize::try_from(from).map_err(|_| Error::ArithmeticOverflow("body range"))?;
            let take = (chunk.len() - from).min(usize::try_from(end - at).unwrap_or(usize::MAX));
            out.extend_from_slice(&chunk[from..from + take]);
            at += take as u64;
        }
        Ok(out)
    }
}

impl Read for BodyFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (file, key, layout) = match &mut self.inner {
            Inner::Plain(file) => return file.read(out),
            Inner::Sealed {
                file, key, layout, ..
            } => (&*file, &*key, &*layout),
        };
        if out.is_empty() || self.at >= self.len {
            return Ok(0);
        }
        let (index, from) = chunk_of(self.at);
        if self.chunk.as_ref().is_none_or(|(held, _)| *held != index) {
            let chunk = read_chunk(file, key, layout, index).map_err(io::Error::other)?;
            self.chunk = Some((index, chunk));
        }
        let Some((_, chunk)) = &self.chunk else {
            return Ok(0);
        };
        let from = usize::try_from(from).map_err(io::Error::other)?;
        let read = out.len().min(chunk.len() - from);
        out[..read].copy_from_slice(&chunk[from..from + read]);
        self.at += read as u64;
        Ok(read)
    }
}
