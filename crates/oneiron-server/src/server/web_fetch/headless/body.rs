//! A headless answer's decoded body, held inline up to a small bound and in
//! an anonymous temporary file past it. The file is deleted when the body is
//! dropped, including when its render cancels a request in flight.

use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, Write};

use oneiron_browser::BrowserBody;

/// The decoded bytes a body keeps in memory before it spills to disk.
pub(super) const INLINE_BODY_BYTES: usize = 256 * 1024;

/// A complete response body that can be read back without first assembling
/// its decoded bytes in memory again.
pub(super) enum SpooledBody {
    Inline(Cursor<Vec<u8>>),
    Spilled { file: File, len: u64 },
}

impl SpooledBody {
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Inline(bytes) => bytes.get_ref().len() as u64,
            Self::Spilled { len, .. } => *len,
        }
    }

    fn write_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match self {
            Self::Inline(bytes)
                if bytes.get_ref().len().saturating_add(chunk.len()) <= INLINE_BODY_BYTES =>
            {
                bytes.get_mut().extend_from_slice(chunk);
            }
            Self::Inline(bytes) => {
                let mut file = tempfile::tempfile()?;
                file.write_all(bytes.get_ref())?;
                file.write_all(chunk)?;
                let len = bytes.get_ref().len() as u64 + chunk.len() as u64;
                *self = Self::Spilled { file, len };
            }
            Self::Spilled { file, len } => {
                file.write_all(chunk)?;
                *len += chunk.len() as u64;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        if let Self::Spilled { file, .. } = self {
            file.flush()?;
            file.rewind()?;
        }
        Ok(())
    }
}

impl Read for SpooledBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Inline(bytes) => bytes.read(out),
            Self::Spilled { file, .. } => file.read(out),
        }
    }
}

impl BrowserBody for SpooledBody {
    fn len(&self) -> u64 {
        SpooledBody::len(self)
    }
}

/// A response-body read failure: the request transport or the local spool.
pub(super) enum ProduceBodyError {
    Request(reqwest::Error),
    Spool(io::Error),
}

impl fmt::Display for ProduceBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Spool(error) => error.fmt(f),
        }
    }
}

impl fmt::Debug for ProduceBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => f.debug_tuple("Request").field(error).finish(),
            Self::Spool(error) => f.debug_tuple("Spool").field(error).finish(),
        }
    }
}

impl std::error::Error for ProduceBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Spool(error) => Some(error),
        }
    }
}

/// Reads a response's decoded chunks into a body that spills past the inline
/// bound. Dropping this future drops the body and removes any temporary file.
pub(super) async fn produce_body(
    mut response: reqwest::Response,
) -> Result<SpooledBody, ProduceBodyError> {
    let mut body = SpooledBody::Inline(Cursor::new(Vec::new()));
    while let Some(chunk) = response.chunk().await.map_err(ProduceBodyError::Request)? {
        body.write_chunk(&chunk).map_err(ProduceBodyError::Spool)?;
    }
    body.finish().map_err(ProduceBodyError::Spool)?;
    Ok(body)
}
