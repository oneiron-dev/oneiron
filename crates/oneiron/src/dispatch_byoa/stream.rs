//! One exhaust stream, held whole however long it runs: in memory up to the
//! inline budget, and past it in an unnamed host temp file, spooled the way a
//! foreign guest's proposed file is ([`SandboxProposalBody`]). The free-space
//! floor of the disk and the run's deadline are the only stops, each a typed
//! refusal; a stream is never cut.
//!
//! In the exhaust artifact a stream within the budget rides the envelope
//! whole. A longer one is stored in budget-sized chunks as earlier versions of
//! the same artifact, and the envelope, appended last as its head, names them
//! in a manifest with the stream's length and BLAKE3 digest. A delete or purge
//! of the artifact releases its whole version chain, so the chunks go with it.

use std::io::Read;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::code_sandbox::{SandboxProposalBody, SandboxProposalBodyWriter};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::origin::smart_http::SpillFloor;

use super::connector::BYOA_EXHAUST_INLINE_BYTES;
use super::error::{ByoaError, ByoaResult};

/// One exhaust stream's bytes, whole. Clones share one spooled file, which is
/// removed when the last clone drops.
#[derive(Clone)]
pub struct ByoaStream(Body);

#[derive(Clone)]
enum Body {
    Inline(Vec<u8>),
    Spooled(SandboxProposalBody),
}

impl ByoaStream {
    /// A stream to capture into: held in memory up to
    /// [`BYOA_EXHAUST_INLINE_BYTES`], then spooled. `floor` is asked before
    /// each write to the spool and `deadline` before each append; they are
    /// the stream's only stops.
    #[must_use]
    pub fn writer(
        floor: Option<Arc<dyn SpillFloor>>,
        deadline: Option<Instant>,
    ) -> ByoaStreamWriter {
        ByoaStreamWriter {
            held: Vec::new(),
            spool: None,
            floor,
            deadline,
        }
    }

    /// Bytes in the stream.
    #[must_use]
    pub fn len(&self) -> u64 {
        match &self.0 {
            Body::Inline(bytes) => bytes.len() as u64,
            Body::Spooled(body) => body.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// BLAKE3 of the whole stream.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        match &self.0 {
            Body::Inline(bytes) => *blake3::hash(bytes).as_bytes(),
            Body::Spooled(body) => body.digest(),
        }
    }

    /// Whether the stream is exactly `bytes`.
    #[must_use]
    pub fn is(&self, bytes: &[u8]) -> bool {
        match &self.0 {
            Body::Inline(held) => held == bytes,
            Body::Spooled(body) => body.is(bytes),
        }
    }

    /// The last `max` bytes, or the whole stream when it is shorter. A read
    /// window over the stream; what the stream holds is never cut.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the spool cannot be read.
    pub fn tail(&self, max: usize) -> ByoaResult<Vec<u8>> {
        let len = self.len();
        let take = len.min(max as u64);
        self.range(len - take, take as usize)
    }

    /// Reads the whole stream from its start, one call's buffer at a time.
    #[must_use]
    pub fn reader(&self) -> Box<dyn Read + Send + '_> {
        match &self.0 {
            Body::Inline(bytes) => Box::new(bytes.as_slice()),
            Body::Spooled(body) => Box::new(body.reader()),
        }
    }

    fn range(&self, offset: u64, len: usize) -> ByoaResult<Vec<u8>> {
        match &self.0 {
            Body::Inline(bytes) => usize::try_from(offset)
                .ok()
                .and_then(|start| bytes.get(start..start.checked_add(len)?))
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    ByoaError::Store(Error::InvalidClaimBody(
                        "byoa exhaust stream range out of bounds",
                    ))
                }),
            Body::Spooled(body) => Ok(body.read_range(offset, len)?),
        }
    }

    /// This stream's envelope form. Within the inline budget it rides the
    /// envelope whole; past it `append` stores it in budget-sized chunks, in
    /// order, and the manifest names the versions `append` returned.
    pub(super) fn to_wire(
        &self,
        append: &mut impl FnMut(&[u8]) -> ByoaResult<u64>,
    ) -> ByoaResult<ByoaStreamWire> {
        let len = self.len();
        let budget = BYOA_EXHAUST_INLINE_BYTES as u64;
        if len <= budget {
            return Ok(ByoaStreamWire::Inline(self.range(0, len as usize)?));
        }
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < len {
            let take = (len - offset).min(budget);
            chunks.push(append(&self.range(offset, take as usize)?)?);
            offset += take;
        }
        Ok(ByoaStreamWire::Chunked(ByoaStreamManifest {
            len,
            digest: self.digest(),
            chunks,
        }))
    }
}

/// Bytes the caller already holds. Stored past the inline budget in chunks,
/// like a spooled stream.
impl From<Vec<u8>> for ByoaStream {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Body::Inline(bytes))
    }
}

impl Default for ByoaStream {
    fn default() -> Self {
        Self(Body::Inline(Vec::new()))
    }
}

/// Two streams are equal when their bytes are: compared directly when both
/// are in memory, else by length and digest.
impl PartialEq for ByoaStream {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Body::Inline(held), Body::Inline(other)) => held == other,
            _ => self.len() == other.len() && self.digest() == other.digest(),
        }
    }
}

impl Eq for ByoaStream {}

impl std::fmt::Debug for ByoaStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByoaStream")
            .field("len", &self.len())
            .field("digest", &blake3::Hash::from_bytes(self.digest()).to_hex())
            .finish()
    }
}

/// A stream being captured. Bytes collect in memory up to the inline budget;
/// past it each full buffer goes on to an unnamed temp file, asked of the
/// floor first. Nothing reads it until [`Self::finish`].
pub struct ByoaStreamWriter {
    held: Vec<u8>,
    spool: Option<SandboxProposalBodyWriter>,
    floor: Option<Arc<dyn SpillFloor>>,
    deadline: Option<Instant>,
}

impl ByoaStreamWriter {
    /// Appends `bytes`, whatever the stream's length so far.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::SpoolDeadline`] once the deadline has passed,
    /// [`ByoaError::SpoolAtDiskFloor`] when a write to the spool would take
    /// the disk below its floor or the disk is full, and [`ByoaError::Store`]
    /// for any other failed write.
    pub fn append(&mut self, bytes: &[u8]) -> ByoaResult<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ByoaError::SpoolDeadline);
        }
        if bytes.len() <= BYOA_EXHAUST_INLINE_BYTES.saturating_sub(self.held.len()) {
            self.held.extend_from_slice(bytes);
            return Ok(());
        }
        // Past the budget the held bytes go on to the spool, then `bytes`:
        // held again when they fit the budget, else written straight on.
        if self.spool.is_none() {
            self.spool = Some(SandboxProposalBody::spool().map_err(spool_error)?);
        }
        if let Some(spool) = &mut self.spool {
            spool_write(spool, self.floor.as_deref(), &self.held)?;
            self.held.clear();
            if bytes.len() > BYOA_EXHAUST_INLINE_BYTES {
                spool_write(spool, self.floor.as_deref(), bytes)?;
            } else {
                self.held.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    /// Settles the stream: in memory when it never passed the budget, else
    /// the spool with the held bytes written after it.
    ///
    /// # Errors
    ///
    /// Returns the floor's refusal or the failure of the spool's last write,
    /// as [`Self::append`] does.
    pub fn finish(self) -> ByoaResult<ByoaStream> {
        let Self {
            held, spool, floor, ..
        } = self;
        let Some(mut spool) = spool else {
            return Ok(ByoaStream(Body::Inline(held)));
        };
        if !held.is_empty() {
            spool_write(&mut spool, floor.as_deref(), &held)?;
        }
        Ok(ByoaStream(Body::Spooled(
            spool.finish().map_err(spool_error)?,
        )))
    }
}

/// One write to a stream's spool, asked of the floor first.
fn spool_write(
    spool: &mut SandboxProposalBodyWriter,
    floor: Option<&dyn SpillFloor>,
    bytes: &[u8],
) -> ByoaResult<()> {
    if floor.is_some_and(|floor| !floor.has_room_for(bytes.len() as u64)) {
        return Err(ByoaError::SpoolAtDiskFloor);
    }
    spool.append(bytes).map_err(spool_error)
}

/// A full disk stops the spool as the floor does; every other failure keeps
/// its own error.
fn spool_error(error: Error) -> ByoaError {
    match error {
        Error::Io(io) if io.kind() == std::io::ErrorKind::StorageFull => {
            ByoaError::SpoolAtDiskFloor
        }
        error => ByoaError::Store(error),
    }
}

/// How one stream rides its exhaust envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ByoaStreamWire {
    /// A stream within the inline budget, whole.
    Inline(Vec<u8>),
    /// A longer stream, stored in chunk versions before the envelope.
    Chunked(ByoaStreamManifest),
}

/// A chunked stream: its length, its BLAKE3 digest and the exhaust artifact's
/// versions that hold its chunks, in order. A chunk equal to the version
/// before it shares that version, so a version may repeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ByoaStreamManifest {
    len: u64,
    digest: [u8; 32],
    chunks: Vec<u64>,
}

impl ByoaStreamWire {
    /// Whether `stream` holds the bytes this form names. A chunked form is
    /// first read back, one chunk at a time, and checked against its manifest.
    pub(super) fn matches(
        &self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        stream: &ByoaStream,
    ) -> ByoaResult<bool> {
        let manifest = match self {
            Self::Inline(bytes) => return Ok(stream.is(bytes)),
            Self::Chunked(manifest) => manifest,
        };
        if stream.len() != manifest.len || stream.digest() != manifest.digest {
            return Ok(false);
        }
        let mut digest = blake3::Hasher::new();
        let mut len = 0_u64;
        for version in &manifest.chunks {
            let chunk = read_chunk(vault, rtxn, artifact_id, *version)?;
            digest.update(&chunk);
            len = len.saturating_add(chunk.len() as u64);
        }
        if len != manifest.len || *digest.finalize().as_bytes() != manifest.digest {
            return Err(unresolved());
        }
        Ok(true)
    }

    /// The stream this form names. A chunked form's chunks are read in `rtxn`
    /// one at a time into a spool and checked against its manifest. A read:
    /// nothing here measures or refuses the stream for its size.
    pub(super) fn resolve(
        self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> ByoaResult<ByoaStream> {
        let manifest = match self {
            Self::Inline(bytes) => return Ok(ByoaStream::from(bytes)),
            Self::Chunked(manifest) => manifest,
        };
        let mut writer = ByoaStream::writer(None, None);
        for version in &manifest.chunks {
            writer.append(&read_chunk(vault, rtxn, artifact_id, *version)?)?;
        }
        let stream = writer.finish()?;
        if stream.len() != manifest.len || stream.digest() != manifest.digest {
            return Err(unresolved());
        }
        Ok(stream)
    }
}

fn read_chunk(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    artifact_id: &EntityId,
    version: u64,
) -> ByoaResult<Vec<u8>> {
    vault
        .read_blob_artifact_version_in_txn(rtxn, artifact_id, version)?
        .ok_or_else(unresolved)
}

/// A manifest whose chunks are missing or do not hold the bytes it names.
fn unresolved() -> ByoaError {
    ByoaError::Store(Error::CorruptedIndex("byoa exhaust stream chunks"))
}
