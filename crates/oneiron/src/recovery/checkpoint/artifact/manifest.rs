//! A sealed artifact's manifest, written and read in bounded pieces (FIX
//! 8823, extends FIX 6374).
//!
//! The manifest names the whole artifact: the image's stream, every body's
//! and payload stream's (each chunk's digest among them), the custody
//! requirement and the payload section. However many there are, its
//! MessagePack encoding is streamed, never held whole, into pieces of at
//! most [`CHUNK_LEN`] bytes, each compressed and sealed on the reserved
//! stream [`MANIFEST_PIECE_STREAM`] as a body's chunks are; a value may
//! cross from one piece into the next. A fixed-small root follows them on
//! [`MANIFEST_STREAM`], and the commitment signs the root's envelope:
//!
//! ```text
//! frame*   the pieces, stream MAX-1, index 0..
//! frame    the root, stream MAX, index 0:
//!          version ‖ kind ‖ vault id ‖ snapshot ‖ epoch ‖ created at
//!          ‖ key header BLAKE3 ‖ where the pieces start and end ‖ their count
//!          ‖ the encoding's length and BLAKE3
//!          ‖ BLAKE3 of each piece's u64be length ‖ envelope, in order
//! ```
//!
//! A reader opens the root, checks that the frames between the pieces'
//! start and the root are exactly the pieces it names, in order, and only
//! then decodes the manifest as it opens one piece at a time; the encoding
//! must end where the last piece does, at the root's length and digest,
//! before anything is made. Nothing caps how many streams, chunks or ids a
//! manifest names; its digests are fixed binary, so its room is read off its
//! shape ([`manifest_room`]).

use std::fs::File;
use std::io::{Read, Write};

use oneiron_crypto::backup::{MANIFEST_PIECE_STREAM, MANIFEST_STREAM};
use serde::{Deserialize, Serialize};

use super::sink::{Sealer, Sink, frame_room, stream_room};
use super::{CHUNK_LEN, codec, frame_at, read_at};
use crate::recovery::checkpoint::payload::PayloadSection;
use crate::store::CustodyRequirement;
use crate::{Error, Result};

/// The most a MessagePack list's header grows past an empty one's: a
/// fixarray's one byte to an array32's five.
const LIST_HEADER_GROWTH: u64 = 4;

/// One stream's line in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StreamEntry {
    pub(super) len: u64,
    /// BLAKE3 of the stream's bytes: the checkpoint id, or the body's name.
    #[serde(with = "digest_bin")]
    pub(super) digest: [u8; 32],
    /// BLAKE3 of each chunk's envelope, in order.
    #[serde(with = "digests_bin")]
    pub(super) chunks: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) version: u16,
    pub(super) kind: u8,
    #[serde(with = "digest_bin")]
    pub(super) vault_id: [u8; 32],
    #[serde(with = "digest_bin")]
    pub(super) snapshot: [u8; 32],
    pub(super) epoch: u64,
    pub(super) created_at: u64,
    /// BLAKE3 of the clear key header.
    #[serde(with = "digest_bin")]
    pub(super) key_header: [u8; 32],
    pub(super) image: StreamEntry,
    pub(super) bodies: Vec<StreamEntry>,
    /// What the image needs of its exterior key custody (KS-4): the
    /// position it had reached and every live id, never a key or a head.
    /// `None` where the vault never published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) custody: Option<CustodyRequirement>,
    /// The ordinary payload's owner compartments (KS-7), never a key, a
    /// wrap, a head or a pad. `None` while CHECKPOINT_PAYLOADS_ENABLED is
    /// off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) payload: Option<PayloadSection>,
    /// Each payload bundle's stream, after every body's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) payload_streams: Vec<StreamEntry>,
}

/// The manifest's root: its fixed bindings, where its pieces lie, and the
/// digests that bind them, the encoding and its envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRoot {
    version: u16,
    kind: u8,
    #[serde(with = "digest_bin")]
    vault_id: [u8; 32],
    #[serde(with = "digest_bin")]
    snapshot: [u8; 32],
    epoch: u64,
    created_at: u64,
    #[serde(with = "digest_bin")]
    key_header: [u8; 32],
    /// Where the first piece's frame starts.
    pieces_at: u64,
    /// Where the pieces end: the root's own frame.
    pieces_end: u64,
    pieces: u32,
    /// The encoding's length and BLAKE3.
    encoded_len: u64,
    #[serde(with = "digest_bin")]
    encoded_blake3: [u8; 32],
    /// BLAKE3 of each piece's u64be envelope length and envelope, in order.
    #[serde(with = "digest_bin")]
    pieces_blake3: [u8; 32],
}

impl ManifestRoot {
    /// Whether the root binds what `manifest` says of itself.
    fn binds(&self, manifest: &Manifest) -> bool {
        self.version == manifest.version
            && self.kind == manifest.kind
            && self.vault_id == manifest.vault_id
            && self.snapshot == manifest.snapshot
            && self.epoch == manifest.epoch
            && self.created_at == manifest.created_at
            && self.key_header == manifest.key_header
    }
}

/// Writes `manifest` at the sink's place: its pieces, then its root.
/// Returns where the root's frame starts and the BLAKE3 of its envelope,
/// which the footer and the commitment name, and how many pieces it took.
///
/// # Errors
///
/// Sealing, encoding and write errors; a claim the floor refuses.
pub(super) fn write_manifest(
    sink: &mut Sink<'_>,
    manifest: &Manifest,
) -> Result<(u64, [u8; 32], u32)> {
    let pieces_at = sink.offset;
    let mut writer = ManifestPieceWriter {
        sink: &mut *sink,
        buffer: Vec::with_capacity(CHUNK_LEN),
        pieces: 0,
        encoded: blake3::Hasher::new(),
        encoded_len: 0,
        sealed: blake3::Hasher::new(),
        failed: None,
    };
    if rmp_serde::encode::write_named(&mut writer, manifest).is_err() {
        return Err(writer.failed.take().unwrap_or_else(codec));
    }
    if !writer.buffer.is_empty() || writer.pieces == 0 {
        writer.piece()?;
    }
    let root = ManifestRoot {
        version: manifest.version,
        kind: manifest.kind,
        vault_id: manifest.vault_id,
        snapshot: manifest.snapshot,
        epoch: manifest.epoch,
        created_at: manifest.created_at,
        key_header: manifest.key_header,
        pieces_at,
        pieces_end: writer.sink.offset,
        pieces: writer.pieces,
        encoded_len: writer.encoded_len,
        encoded_blake3: *writer.encoded.finalize().as_bytes(),
        pieces_blake3: *writer.sealed.finalize().as_bytes(),
    };
    let pieces = writer.pieces;
    let root_at = sink.offset;
    let bytes = rmp_serde::to_vec_named(&root).map_err(|_| codec())?;
    let envelope = sink.sealer.seal(MANIFEST_STREAM, 0, &bytes)?;
    sink.frame(&envelope)?;
    Ok((root_at, *blake3::hash(&envelope).as_bytes(), pieces))
}

/// Opens the manifest whose root is the frame at `root_at`, its envelope
/// `root`, the bytes the verified commitment names: the root, then the
/// exact frames between its pieces' start (never before `first_frame`) and
/// itself, checked as the pieces it names in order, and only then the
/// encoding, piece by piece, which must end at the last piece, at the
/// root's length and digest. Returns the manifest and where its pieces
/// start, which is where the streams' chunks end.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for anything that does not check; a key that
/// does not open a piece.
pub(super) fn read_manifest(
    file: &mut File,
    sealer: &Sealer<'_>,
    (root_at, root): (u64, &[u8]),
    first_frame: u64,
) -> Result<(Manifest, u64)> {
    let root: ManifestRoot =
        rmp_serde::from_slice(&sealer.open(MANIFEST_STREAM, 0, root)?).map_err(|_| codec())?;
    if root.pieces_end != root_at
        || root.pieces_at < first_frame
        || root.pieces_at >= root.pieces_end
        || root.pieces == 0
    {
        return Err(codec());
    }
    let mut frames = Vec::new();
    let mut sealed = blake3::Hasher::new();
    let mut at = root.pieces_at;
    while at < root.pieces_end {
        let (len, next) = frame_at(file, at)?;
        let envelope = read_at(file, at + 4, len)?;
        sealed.update(&len.to_be_bytes());
        sealed.update(&envelope);
        frames.push((at + 4, len));
        at = next;
    }
    if at != root.pieces_end
        || u32::try_from(frames.len()).ok() != Some(root.pieces)
        || *sealed.finalize().as_bytes() != root.pieces_blake3
    {
        return Err(codec());
    }
    let mut reader = ManifestPieceReader {
        file,
        sealer,
        frames: frames.into_iter(),
        index: 0,
        piece: Vec::new(),
        at: 0,
        encoded: blake3::Hasher::new(),
        encoded_len: 0,
        failed: None,
    };
    let manifest: Manifest = match rmp_serde::from_read(&mut reader) {
        Ok(manifest) => manifest,
        Err(_) => return Err(reader.failed.take().unwrap_or_else(codec)),
    };
    let ended = reader.at == reader.piece.len() && reader.frames.next().is_none();
    if !ended
        || reader.encoded_len != root.encoded_len
        || *reader.encoded.finalize().as_bytes() != root.encoded_blake3
        || !root.binds(&manifest)
    {
        return Err(codec());
    }
    Ok((manifest, root.pieces_at))
}

/// The most the manifest of these streams takes on the disk, its pieces
/// and its root (FIX 8823): the encoding's bound read off the shape it will
/// have (each stream's line at its widest, the custody requirement and the
/// payload section as they are, every chunk's digest fixed binary, every
/// list's header at its widest), framed as a stream's chunks are, and the
/// root's frame at its widest. `bodies` and `payload_streams` are each
/// stream's length; nothing is capped.
///
/// # Errors
///
/// An encoding that fails.
pub(super) fn manifest_room(
    kind: u8,
    custody: Option<&CustodyRequirement>,
    payload: Option<&PayloadSection>,
    image: u64,
    bodies: &[u64],
    payload_streams: &[u64],
) -> Result<u64> {
    let widest = || StreamEntry {
        len: u64::MAX,
        digest: [0; 32],
        chunks: Vec::new(),
    };
    let shape = Manifest {
        version: u16::MAX,
        kind,
        vault_id: [0; 32],
        snapshot: [0; 32],
        epoch: u64::MAX,
        created_at: u64::MAX,
        key_header: [0; 32],
        image: widest(),
        bodies: bodies.iter().map(|_| widest()).collect(),
        custody: custody.cloned(),
        payload: payload.cloned(),
        payload_streams: payload_streams.iter().map(|_| widest()).collect(),
    };
    let digest = encoded_len(&Bin(&[0; 32]))?;
    let chunk = CHUNK_LEN as u64;
    let lines = std::iter::once(image)
        .chain(bodies.iter().copied())
        .chain(payload_streams.iter().copied())
        .fold(0_u64, |sum, len| {
            sum.saturating_add(LIST_HEADER_GROWTH)
                .saturating_add(len.div_ceil(chunk).saturating_mul(digest))
        });
    let encoding = encoded_len(&shape)?.saturating_add(lines);
    let root = ManifestRoot {
        version: u16::MAX,
        kind,
        vault_id: [0; 32],
        snapshot: [0; 32],
        epoch: u64::MAX,
        created_at: u64::MAX,
        key_header: [0; 32],
        pieces_at: u64::MAX,
        pieces_end: u64::MAX,
        pieces: u32::MAX,
        encoded_len: u64::MAX,
        encoded_blake3: [0; 32],
        pieces_blake3: [0; 32],
    };
    let root = usize::try_from(encoded_len(&root)?).map_err(|_| codec())?;
    Ok(stream_room(encoding).saturating_add(frame_room(root)))
}

/// How many bytes `value`'s named MessagePack encoding takes, counted as it
/// is written and never held.
fn encoded_len<T: Serialize + ?Sized>(value: &T) -> Result<u64> {
    let mut counter = Counter(0);
    rmp_serde::encode::write_named(&mut counter, value).map_err(|_| codec())?;
    Ok(counter.0)
}

/// A writer that only counts.
struct Counter(u64);

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The manifest's encoding as it is written: each [`CHUNK_LEN`] bytes of it
/// sealed and framed as one piece, the last when it ends.
struct ManifestPieceWriter<'s, 'k> {
    sink: &'s mut Sink<'k>,
    buffer: Vec<u8>,
    pieces: u32,
    encoded: blake3::Hasher,
    encoded_len: u64,
    sealed: blake3::Hasher,
    /// What failed a piece, which the encoder sees only as a write error.
    failed: Option<Error>,
}

impl ManifestPieceWriter<'_, '_> {
    /// Seals and frames what the buffer holds as the next piece.
    fn piece(&mut self) -> Result<()> {
        let envelope = self
            .sink
            .sealer
            .seal(MANIFEST_PIECE_STREAM, self.pieces, &self.buffer)?;
        self.sealed.update(&(envelope.len() as u64).to_be_bytes());
        self.sealed.update(&envelope);
        self.sink.frame(&envelope)?;
        self.pieces = self.pieces.checked_add(1).ok_or_else(codec)?;
        self.buffer.clear();
        Ok(())
    }
}

impl Write for ManifestPieceWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let take = bytes.len().min(CHUNK_LEN - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..take]);
        self.encoded.update(&bytes[..take]);
        self.encoded_len = self.encoded_len.saturating_add(take as u64);
        if self.buffer.len() == CHUNK_LEN
            && let Err(error) = self.piece()
        {
            self.failed = Some(error);
            return Err(std::io::Error::other("a checkpoint manifest piece failed"));
        }
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The manifest's encoding as it is read: each piece opened, after the
/// pieces were checked against the root, only as the decoder reaches it.
struct ManifestPieceReader<'f, 'k> {
    file: &'f mut File,
    sealer: &'f Sealer<'k>,
    /// Each piece's frame (offset, length), in order.
    frames: std::vec::IntoIter<(u64, u64)>,
    index: u32,
    piece: Vec<u8>,
    at: usize,
    encoded: blake3::Hasher,
    encoded_len: u64,
    /// What failed a piece, which the decoder sees only as a read error.
    failed: Option<Error>,
}

impl Read for ManifestPieceReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at == self.piece.len() {
            let Some((offset, len)) = self.frames.next() else {
                return Ok(0);
            };
            let opened = read_at(self.file, offset, len).and_then(|envelope| {
                self.sealer
                    .open(MANIFEST_PIECE_STREAM, self.index, &envelope)
            });
            match opened {
                Ok(piece) => {
                    self.encoded.update(&piece);
                    self.encoded_len = self.encoded_len.saturating_add(piece.len() as u64);
                    self.piece = piece;
                    self.at = 0;
                    self.index = self.index.saturating_add(1);
                }
                Err(error) => {
                    self.failed = Some(error);
                    return Err(std::io::Error::other("a checkpoint manifest piece failed"));
                }
            }
        }
        let read = out.len().min(self.piece.len() - self.at);
        out[..read].copy_from_slice(&self.piece[self.at..self.at + read]);
        self.at += read;
        Ok(read)
    }
}

/// A digest as MessagePack binary: the same width whatever its bytes.
struct Bin<'a>(&'a [u8; 32]);

impl Serialize for Bin<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// A digest read back from MessagePack binary.
struct Digest([u8; 32]);

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Digest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 32-byte digest")
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<Digest, E> {
                <[u8; 32]>::try_from(bytes)
                    .map(Digest)
                    .map_err(|_| E::invalid_length(bytes.len(), &self))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// `#[serde(with)]` for one digest as fixed binary.
mod digest_bin {
    use serde::{Deserialize, Serialize};

    pub(super) fn serialize<S: serde::Serializer>(
        digest: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::Bin(digest).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        super::Digest::deserialize(deserializer).map(|digest| digest.0)
    }
}

/// `#[serde(with)]` for a list of digests, each as fixed binary.
mod digests_bin {
    use serde::Deserialize;

    pub(super) fn serialize<S: serde::Serializer>(
        digests: &[[u8; 32]],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(digests.iter().map(super::Bin))
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        Ok(Vec::<super::Digest>::deserialize(deserializer)?
            .into_iter()
            .map(|digest| digest.0)
            .collect())
    }
}
