//! Owned bytes returned by one outbound send, shared without copying them.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::{Result, Vault};

/// The raw body of one send, not authority to read any other result. A clone
/// shares its owner; each reader has its own position and range. Diagnostics
/// reveal the byte count only.
#[derive(Clone)]
pub struct RawOutboundBody {
    storage: Arc<Storage>,
    start: u64,
    len: u64,
}

enum Storage {
    Bytes(Zeroizing<Vec<u8>>),
    File(Mutex<File>),
}

impl RawOutboundBody {
    /// Takes the transport's existing allocation without copying it.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            start: 0,
            storage: Arc::new(Storage::Bytes(Zeroizing::new(bytes))),
        }
    }

    /// Reads an entire body into a vault-owned anonymous spool, without an
    /// allocation based on the response's length. The file is gone when its
    /// last body or reader drops, as an archive spool is.
    pub fn read_spooled(vault: &Vault, mut input: impl Read) -> Result<Self> {
        let mut file = vault.archive_spool_file()?;
        let mut chunk = Zeroizing::new([0u8; 8192]);
        let mut len = 0u64;
        loop {
            let n = match input.read(&mut *chunk) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if n == 0 {
                break;
            }
            file.write_all(&chunk[..n])?;
            len = len
                .checked_add(n as u64)
                .ok_or_else(|| io::Error::other("an outbound body length overflowed"))?;
        }
        Ok(Self {
            storage: Arc::new(Storage::File(Mutex::new(file))),
            start: 0,
            len,
        })
    }

    /// Clears an already validated JSON reply with the send's own door
    /// value. Unchanged JSON retains its original bytes; changed JSON uses
    /// the same parsed-value comparison and compact encoding as clear_bytes.
    /// This adapter still holds parsed Values; it is not a streamed JSON wall.
    pub fn cleared_json(
        self,
        vault: &Vault,
        value: &crate::secret_custody::SentValue<'_>,
    ) -> Result<Self> {
        if matches!(self.storage.as_ref(), Storage::Bytes(_)) {
            let mut bytes = self.into_bytes()?;
            value.clear_bytes(&mut bytes);
            return Ok(Self::from_bytes(bytes));
        }
        let mut parsed: serde_json::Value =
            serde_json::from_reader(super::ZeroizingBufReader::new(self.reader()))
                .map_err(io::Error::other)?;
        let before = parsed.clone();
        value.clear_json(&mut parsed);
        let changed = parsed != before;
        super::zeroize_json(before);
        if !changed {
            super::zeroize_json(parsed);
            return Ok(self);
        }
        let cleared = (|| -> Result<Self> {
            let mut file = vault.archive_spool_file()?;
            serde_json::to_writer(&mut file, &parsed).map_err(io::Error::other)?;
            let len = file.stream_position()?;
            Ok(Self {
                storage: Arc::new(Storage::File(Mutex::new(file))),
                start: 0,
                len,
            })
        })();
        super::zeroize_json(parsed);
        cleared
    }

    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.len
    }

    /// A view into these same bytes. It keeps the original owner alive,
    /// rather than cloning a file descriptor whose seek position is shared.
    pub fn range(&self, start: u64, len: u64) -> io::Result<Self> {
        if start > self.len || len > self.len - start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an outbound body range is outside its bytes",
            ));
        }
        Ok(Self {
            storage: Arc::clone(&self.storage),
            start: self.start + start,
            len,
        })
    }

    #[must_use]
    pub fn reader(&self) -> RawOutboundBodyReader {
        RawOutboundBodyReader {
            body: self.clone(),
            at: 0,
        }
    }

    /// The explicit whole-body adapter for a consumer whose stored format
    /// still owns a Vec. An unshared, complete byte allocation moves as-is.
    pub fn into_bytes(self) -> io::Result<Vec<u8>> {
        let Self {
            storage,
            start,
            len,
        } = self;
        let storage = match Arc::try_unwrap(storage) {
            Ok(Storage::Bytes(mut bytes)) if start == 0 && len == bytes.len() as u64 => {
                return Ok(std::mem::take(&mut *bytes));
            }
            Ok(storage) => Arc::new(storage),
            Err(storage) => storage,
        };
        let body = Self {
            storage,
            start,
            len,
        };
        let mut bytes = Zeroizing::new(Vec::new());
        body.reader().read_to_end(&mut bytes)?;
        Ok(std::mem::take(&mut *bytes))
    }
}

impl From<Vec<u8>> for RawOutboundBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for RawOutboundBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawOutboundBody")
            .field("bytes", &self.len)
            .finish()
    }
}

/// A reader's logical position never changes another reader's position.
/// The spool's seek and read share one lock, on every supported platform.
pub struct RawOutboundBodyReader {
    body: RawOutboundBody,
    at: u64,
}

impl Read for RawOutboundBodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.body.len - self.at)
            .unwrap_or(usize::MAX)
            .min(out.len());
        if count == 0 {
            return Ok(0);
        }
        let at = self.body.start + self.at;
        let n = match self.body.storage.as_ref() {
            Storage::Bytes(bytes) => {
                let at = at as usize;
                out[..count].copy_from_slice(&bytes[at..at + count]);
                count
            }
            Storage::File(file) => {
                let mut file = file
                    .lock()
                    .map_err(|_| io::Error::other("an outbound body spool lock was poisoned"))?;
                file.seek(SeekFrom::Start(at))?;
                file.read(&mut out[..count])?
            }
        };
        self.at += n as u64;
        Ok(n)
    }
}
