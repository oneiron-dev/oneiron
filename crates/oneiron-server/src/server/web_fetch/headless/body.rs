//! A headless answer's decoded body, held inline up to a small bound and in
//! an anonymous temporary file past it. The file is deleted when the body is
//! dropped, including when its render cancels a request in flight.

use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, Write};
use std::time::Duration;

use oneiron::Vault;
use oneiron_browser::BrowserBody;
use oneiron_container::{HostNetPermit, saturated_floor};

/// The decoded bytes a body keeps in memory before it spills to disk.
pub(super) const INLINE_BODY_BYTES: usize = 256 * 1024;

/// How long the producer waits before it asks the floor's byte reserve
/// again, once it was full: the same 50 ms poll as the paused-request
/// driver's byte wait. Only paces; no wait ends a request.
const BYTE_WAIT: Duration = Duration::from_millis(50);

/// A complete response body that can be read back without first assembling
/// its decoded bytes in memory again. `held` keeps the floor's room for the
/// bytes it holds, released when the body drops.
pub(super) enum SpooledBody {
    Inline {
        bytes: Cursor<Vec<u8>>,
        held: Vec<HostNetPermit>,
    },
    Spilled {
        file: File,
        len: u64,
        held: Vec<HostNetPermit>,
    },
}

impl SpooledBody {
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Inline { bytes, .. } => bytes.get_ref().len() as u64,
            Self::Spilled { len, .. } => *len,
        }
    }

    fn write_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match self {
            Self::Inline { bytes, .. }
                if bytes.get_ref().len().saturating_add(chunk.len()) <= INLINE_BODY_BYTES =>
            {
                bytes.get_mut().extend_from_slice(chunk);
            }
            Self::Inline { bytes, held } => {
                let mut file = tempfile::tempfile()?;
                file.write_all(bytes.get_ref())?;
                file.write_all(chunk)?;
                let len = bytes.get_ref().len() as u64 + chunk.len() as u64;
                let held = std::mem::take(held);
                *self = Self::Spilled { file, len, held };
            }
            Self::Spilled { file, len, .. } => {
                file.write_all(chunk)?;
                *len += chunk.len() as u64;
            }
        }
        Ok(())
    }

    fn push_permit(&mut self, permit: HostNetPermit) {
        match self {
            Self::Inline { held, .. } | Self::Spilled { held, .. } => held.push(permit),
        }
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
            Self::Inline { bytes, .. } => bytes.read(out),
            Self::Spilled { file, .. } => file.read(out),
        }
    }
}

impl BrowserBody for SpooledBody {
    fn len(&self) -> u64 {
        SpooledBody::len(self)
    }
}

/// A response-body read failure: the request transport, the local
/// spool, or the response past the host's bound.
pub(super) enum ProduceBodyError {
    Request(reqwest::Error),
    Spool(io::Error),
    /// The decoded body ran past `limit` bytes (FIX 12222): a request
    /// failure, never a destination refusal. Names only the limit.
    TooLarge { limit: u64 },
}

impl fmt::Display for ProduceBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Spool(error) => error.fmt(f),
            Self::TooLarge { limit } => {
                write!(f, "headless response body past the {limit}-byte bound")
            }
        }
    }
}

impl fmt::Debug for ProduceBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => f.debug_tuple("Request").field(error).finish(),
            Self::Spool(error) => f.debug_tuple("Spool").field(error).finish(),
            Self::TooLarge { limit } => {
                f.debug_struct("TooLarge").field("limit", limit).finish()
            }
        }
    }
}

impl std::error::Error for ProduceBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Spool(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

/// Reads a response's decoded chunks into a body that spills past the inline
/// bound, refusing past `max_response_bytes` (FIX 12222): the count is taken
/// before each chunk is spooled, so the temporary file never holds more than
/// the cap, and each chunk's bytes are charged to the floor the vault's host
/// lent ([`Vault::acquire_host_net_bytes`]) as they arrive, held with the
/// body until it drops. Over-cap drops the response and the partial spool.
/// Dropping this future drops the body and removes any temporary file.
pub(super) async fn produce_body(
    mut response: reqwest::Response,
    max_response_bytes: usize,
    vault: &Vault,
) -> Result<SpooledBody, ProduceBodyError> {
    let limit = max_response_bytes as u64;
    let mut body = SpooledBody::Inline {
        bytes: Cursor::new(Vec::new()),
        held: Vec::new(),
    };
    let mut total: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(ProduceBodyError::Request)? {
        let len = chunk.len() as u64;
        if total.saturating_add(len) > limit {
            return Err(ProduceBodyError::TooLarge { limit });
        }
        let permit = hold_bytes(vault, len).await?;
        body.write_chunk(&chunk).map_err(ProduceBodyError::Spool)?;
        total += len;
        body.push_permit(permit);
    }
    body.finish().map_err(ProduceBodyError::Spool)?;
    Ok(body)
}

/// Room for `bytes` on the floor the vault's host lent, waited for at
/// [`BYTE_WAIT`] while the reserve is full. A vault no host lent one charges
/// nothing. Anything but back-pressure fails through the spool arm: a floor
/// error names only the floor, no URL.
async fn hold_bytes(vault: &Vault, bytes: u64) -> Result<HostNetPermit, ProduceBodyError> {
    loop {
        match vault.acquire_host_net_bytes(bytes) {
            Ok(permit) => return Ok(permit),
            Err(error) if saturated_floor(&error).is_some() => {
                tokio::time::sleep(BYTE_WAIT).await;
            }
            Err(error) => return Err(ProduceBodyError::Spool(error)),
        }
    }
}
