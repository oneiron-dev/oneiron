//! The chunk-sync stream an HTTP exchange carries each way (FIX 145): an
//! envelope ([`CHUNK_SYNC_VERSION`] and its MessagePack) cut into frames,
//! then an end frame. A frame is its length, a big-endian `u32` from 1 to
//! [`MAX_CHUNK_SYNC_FRAME`], and its bytes; the end frame is a length of 0.
//!
//! Neither side holds a stream whole or refuses one for its length: a writer
//! holds the one frame it fills, and a reader decodes as the frames arrive. A
//! request is read field by field, each through its byte cap, and its HAVE and
//! WANT hold no more hashes than the manifest of the object it names: each
//! hash is checked against it as it arrives. A stream that ends before its end
//! frame, or holds anything after it, is no exchange, so a reply cut short
//! reads as a broken transfer, never a shorter one, with no length declared
//! ahead of it.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::{self, BufReader, Read, Write};
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, SeqAccess, Visitor};

use super::{
    CHUNK_SYNC_VERSION, ChunkPageCursor, ChunkRead, ChunkSyncRequest, ChunkSyncResponse,
    MAX_CHUNK_SYNC_FRAME, invalid,
};
use crate::error::Result;

/// The bytes a writer puts in each frame but its last: one stored chunk's
/// most, so a writer holds one such frame at a time.
pub const CHUNK_STREAM_FRAME_BYTES: usize = crate::origin::lfs::LFS_CHUNK_MAX;

/// The most bytes a request's selector takes as it is read: far above any
/// grant selector's codec bytes. A longer one is a malformed request, refused
/// there (CHUNK-STREAM-SELECTOR-AND-WHY-UNBOUNDED).
pub const MAX_CHUNK_REQUEST_SELECTOR_BYTES: usize = 1024 * 1024;

/// The most bytes a request's read of a marked object takes as it is read:
/// the agent's one-line why, which is all of it but a few bytes of framing,
/// with room far past any honest one. A longer one is a malformed request,
/// refused there (CHUNK-STREAM-SELECTOR-AND-WHY-UNBOUNDED).
pub const MAX_CHUNK_REQUEST_READ_BYTES: usize = 64 * 1024;

/// The most bytes any other field of a request, or one HAVE or WANT hash,
/// takes as it is read: a `u64`, a 32-byte hash written as 32 integers of up
/// to 9 bytes each, a list's length or the cursor, in any MessagePack
/// encoding of it. No field is held past its size, whatever its marker
/// declares.
const MAX_REQUEST_FIELD_BYTES: usize = 512;

/// The bytes a frame's length takes: a big-endian `u32`.
const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();

/// What a request's array holds, named in the refusal of one that ends early.
const REQUEST_FIELDS: &str = "a chunk-sync request of seven fields";

const _: () = assert!(CHUNK_STREAM_FRAME_BYTES <= MAX_CHUNK_SYNC_FRAME);
const _: () = assert!(MAX_CHUNK_SYNC_FRAME <= u32::MAX as usize);

/// Writes `request` as the stream an HTTP exchange's request carries. Its
/// HAVE and WANT may hold any number of hashes (FIX 8183): no length bounds
/// a stream.
pub fn write_chunk_request_stream(request: &ChunkSyncRequest, sink: impl Write) -> Result<()> {
    write_stream(request, sink)
}

/// Reads one request from the stream an HTTP exchange's request carries,
/// decoded as its frames arrive, holding no field past its byte cap and no
/// more of its HAVE and WANT than the manifest of the object it names (FIX
/// CHUNK-STREAM-DECODE-UNBOUNDED-MEMORY; CHUNK-STREAM-MEMORY-BOUND = A).
///
/// Once the request's oid and selector are read, `manifest_chunks` answers
/// the chunk hashes of that object's stored manifest, or fails for an object
/// with none. Each HAVE and WANT hash is checked as it arrives, and only a
/// hash the manifest names is held. A request that fails a manifest check (no
/// manifest, a hash the manifest does not name, a WANT hash its WANT already
/// named, or a WANT hash the HAVE names) holds no hash from there on, is read
/// on to its end frame, and is refused only then. So an absent object, a
/// withheld one and a hash its manifest lacks take the same read of the
/// stream, and a body that breaks before its end is a broken body whatever
/// the manifest holds (REVIEW-10608 P1 1). A HAVE hash its HAVE already named
/// is held once, since an answer reads the HAVE as a set. A field past its cap
/// ([`MAX_CHUNK_REQUEST_SELECTOR_BYTES`], [`MAX_CHUNK_REQUEST_READ_BYTES`], or
/// a fixed field's size) refuses the request at its cap, which no manifest
/// decides. No count refuses an exchange (FIX 8183): one that names every
/// chunk of any manifest decodes whole.
pub fn read_chunk_request_stream(
    source: impl Read,
    manifest_chunks: impl FnOnce(&[u8; 32]) -> Result<BTreeSet<[u8; 32]>>,
) -> Result<ChunkSyncRequest> {
    let room = Cell::new(Some(MAX_REQUEST_FIELD_BYTES));
    let refused = Cell::new(false);
    let request = read_stream_seeded(
        source,
        &room,
        RequestSeed {
            manifest_chunks,
            room: &room,
            refused: &refused,
        },
    )?;
    if refused.get() {
        return Err(invalid());
    }
    Ok(request)
}

/// Writes `response` as the stream an HTTP exchange's reply carries, a frame
/// at a time, into `sink` as it takes them: its encoding is never held
/// whole.
pub fn write_chunk_response_stream(response: &ChunkSyncResponse, sink: impl Write) -> Result<()> {
    write_stream(response, sink)
}

/// Reads one reply from the stream an HTTP exchange's reply carries, as its
/// frames arrive. A reply cut short before its end frame is no reply.
pub fn read_chunk_response_stream(source: impl Read) -> Result<ChunkSyncResponse> {
    read_stream(source)
}

/// A request read field by field, each through its byte cap, its HAVE and
/// WANT checked hash by hash against the manifest of the object it names.
struct RequestSeed<'r, F> {
    manifest_chunks: F,
    /// The bytes the field being read may still take.
    room: &'r Cell<Option<usize>>,
    /// Whether a manifest check failed: the request is read to its end and
    /// refused then.
    refused: &'r Cell<bool>,
}

impl<'de, F> DeserializeSeed<'de> for RequestSeed<'_, F>
where
    F: FnOnce(&[u8; 32]) -> Result<BTreeSet<[u8; 32]>>,
{
    type Value = ChunkSyncRequest;

    /// MessagePack writes a request as the array of its seven fields, in
    /// order.
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<ChunkSyncRequest, D::Error> {
        deserializer.deserialize_tuple(7, self)
    }
}

impl<'de, F> Visitor<'de> for RequestSeed<'_, F>
where
    F: FnOnce(&[u8; 32]) -> Result<BTreeSet<[u8; 32]>>,
{
    type Value = ChunkSyncRequest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(REQUEST_FIELDS)
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<ChunkSyncRequest, A::Error> {
        let Self {
            manifest_chunks,
            room,
            refused,
        } = self;
        let fixed = MAX_REQUEST_FIELD_BYTES;
        let request = field(&mut seq, room, (0, fixed), PhantomData::<u64>)?;
        let oid = field(&mut seq, room, (1, fixed), PhantomData::<[u8; 32]>)?;
        let selector = field(
            &mut seq,
            room,
            (2, MAX_CHUNK_REQUEST_SELECTOR_BYTES),
            PhantomData::<Vec<u8>>,
        )?;
        // An object with no manifest is read on like any other and refused
        // at the end: its HAVE and WANT then hold nothing.
        let held = manifest_chunks(&oid).unwrap_or_else(|_| {
            refused.set(true);
            BTreeSet::new()
        });
        let (have, named) = field(
            &mut seq,
            room,
            (3, fixed),
            HaveList {
                held: &held,
                room,
                refused,
            },
        )?;
        let want = field(
            &mut seq,
            room,
            (4, fixed),
            WantList {
                held: &held,
                have: &named,
                room,
                refused,
            },
        )?;
        let cursor = field(
            &mut seq,
            room,
            (5, fixed),
            PhantomData::<Option<ChunkPageCursor>>,
        )?;
        let read = field(
            &mut seq,
            room,
            (6, MAX_CHUNK_REQUEST_READ_BYTES),
            PhantomData::<Option<ChunkRead>>,
        )?;
        // An array that runs on past its seventh field is refused unread.
        room.set(Some(0));
        Ok(ChunkSyncRequest {
            request,
            oid,
            selector,
            have,
            want,
            cursor,
            read,
        })
    }
}

/// Reads a request's field `index` with `seed`, through a cap of `cap`
/// bytes; an array that ends before it is refused.
fn field<'de, A: SeqAccess<'de>, S: DeserializeSeed<'de>>(
    seq: &mut A,
    room: &Cell<Option<usize>>,
    (index, cap): (usize, usize),
    seed: S,
) -> std::result::Result<S::Value, A::Error> {
    room.set(Some(cap));
    seq.next_element_seed(seed)?
        .ok_or_else(|| <A::Error as serde::de::Error>::invalid_length(index, &REQUEST_FIELDS))
}

/// Reads the next hash of a HAVE or WANT, through a cap of one field's bytes.
fn next_hash<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    room: &Cell<Option<usize>>,
) -> std::result::Result<Option<[u8; 32]>, A::Error> {
    room.set(Some(MAX_REQUEST_FIELD_BYTES));
    seq.next_element()
}

/// A HAVE read hash by hash: one the manifest does not name fails the
/// request's manifest check there (`refused`), after which no hash is held,
/// and one the HAVE already named is held once. Its value is the HAVE in its
/// order and the set of its hashes.
struct HaveList<'h> {
    held: &'h BTreeSet<[u8; 32]>,
    room: &'h Cell<Option<usize>>,
    refused: &'h Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for HaveList<'_> {
    type Value = (Vec<[u8; 32]>, BTreeSet<[u8; 32]>);

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for HaveList<'_> {
    type Value = (Vec<[u8; 32]>, BTreeSet<[u8; 32]>);

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a HAVE of chunk hashes the manifest names")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut list = Vec::new();
        let mut named = BTreeSet::new();
        while let Some(hash) = next_hash(&mut seq, self.room)? {
            if self.refused.get() {
                continue;
            }
            if !self.held.contains(&hash) {
                self.refused.set(true);
                list = Vec::new();
                named = BTreeSet::new();
                continue;
            }
            if named.insert(hash) {
                list.push(hash);
            }
        }
        Ok((list, named))
    }
}

/// A WANT, or none, read hash by hash as [`WantHashes`] reads it.
struct WantList<'h> {
    held: &'h BTreeSet<[u8; 32]>,
    have: &'h BTreeSet<[u8; 32]>,
    room: &'h Cell<Option<usize>>,
    refused: &'h Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for WantList<'_> {
    type Value = Option<Vec<[u8; 32]>>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de> Visitor<'de> for WantList<'_> {
    type Value = Option<Vec<[u8; 32]>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a WANT of chunk hashes the manifest names, or none")
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer
            .deserialize_seq(WantHashes {
                held: self.held,
                have: self.have,
                room: self.room,
                refused: self.refused,
            })
            .map(Some)
    }
}

/// A WANT's hashes as they arrive: one the manifest does not name, one the
/// HAVE names, or one the WANT already named fails the request's manifest
/// check there (`refused`), after which no hash is held.
struct WantHashes<'h> {
    held: &'h BTreeSet<[u8; 32]>,
    have: &'h BTreeSet<[u8; 32]>,
    room: &'h Cell<Option<usize>>,
    refused: &'h Cell<bool>,
}

impl<'de> Visitor<'de> for WantHashes<'_> {
    type Value = Vec<[u8; 32]>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WANT hashes the manifest names and the HAVE does not")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut list = Vec::new();
        let mut named = BTreeSet::new();
        while let Some(hash) = next_hash(&mut seq, self.room)? {
            if self.refused.get() {
                continue;
            }
            if !self.held.contains(&hash) || self.have.contains(&hash) || !named.insert(hash) {
                self.refused.set(true);
                list = Vec::new();
                named = BTreeSet::new();
                continue;
            }
            list.push(hash);
        }
        Ok(list)
    }
}

fn write_stream<T: serde::Serialize>(value: &T, sink: impl Write) -> Result<()> {
    let mut frames = FrameWriter::new(sink);
    frames.write_all(&[CHUNK_SYNC_VERSION])?;
    rmp_serde::encode::write(&mut frames, value).map_err(|_| invalid())?;
    frames.finish()?;
    Ok(())
}

fn read_stream<T: serde::de::DeserializeOwned>(source: impl Read) -> Result<T> {
    read_stream_seeded(source, &Cell::new(None), PhantomData::<T>)
}

/// Reads one value with `seed` from a stream as its frames arrive, each byte
/// through the cap `room` holds for the field being read (`None`: no cap).
fn read_stream_seeded<'de, S: DeserializeSeed<'de>>(
    source: impl Read,
    room: &Cell<Option<usize>>,
    seed: S,
) -> Result<S::Value> {
    let mut frames = FrameReader::new(BufReader::new(source));
    let mut version = [0; 1];
    frames.read_exact(&mut version).map_err(|_| invalid())?;
    if version[0] != CHUNK_SYNC_VERSION {
        return Err(invalid());
    }
    let fields = FieldCapped {
        frames: &mut frames,
        room,
    };
    let value = seed
        .deserialize(&mut rmp_serde::Deserializer::new(fields))
        .map_err(|_| invalid())?;
    frames.finish().map_err(|_| invalid())?;
    Ok(value)
}

/// A stream's bytes, read through the cap of the field being decoded: a read
/// past it fails, and the decode with it.
struct FieldCapped<'r, R> {
    frames: R,
    /// The bytes the field being read may still take; `None` reads uncapped.
    room: &'r Cell<Option<usize>>,
}

impl<R: Read> Read for FieldCapped<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let Some(room) = self.room.get() else {
            return self.frames.read(output);
        };
        if room == 0 && !output.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk-sync request field past its byte cap",
            ));
        }
        let wanted = output.len().min(room);
        let count = self.frames.read(&mut output[..wanted])?;
        self.room.set(Some(room.saturating_sub(count)));
        Ok(count)
    }
}

/// The bytes handed to it, sent on as frames of [`CHUNK_STREAM_FRAME_BYTES`]
/// each but the last, and the end frame at its finish.
struct FrameWriter<W> {
    sink: W,
    /// The frame being filled: room for its length, then its bytes.
    frame: Vec<u8>,
}

impl<W: Write> FrameWriter<W> {
    fn new(sink: W) -> Self {
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + CHUNK_STREAM_FRAME_BYTES);
        frame.resize(FRAME_HEADER_BYTES, 0);
        Self { sink, frame }
    }

    /// Sends the frame being filled, when it holds any bytes.
    fn send(&mut self) -> io::Result<()> {
        let length = self.frame.len() - FRAME_HEADER_BYTES;
        if length == 0 {
            return Ok(());
        }
        let header =
            u32::try_from(length).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header.to_be_bytes());
        self.sink.write_all(&self.frame)?;
        self.frame.truncate(FRAME_HEADER_BYTES);
        Ok(())
    }

    /// Sends the last frame, then the end frame.
    fn finish(mut self) -> io::Result<()> {
        self.send()?;
        self.sink.write_all(&[0; FRAME_HEADER_BYTES])?;
        self.sink.flush()
    }
}

impl<W: Write> Write for FrameWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let room = FRAME_HEADER_BYTES + CHUNK_STREAM_FRAME_BYTES - self.frame.len();
        let count = bytes.len().min(room);
        self.frame.extend_from_slice(&bytes[..count]);
        if self.frame.len() == FRAME_HEADER_BYTES + CHUNK_STREAM_FRAME_BYTES {
            self.send()?;
        }
        Ok(count)
    }

    /// A frame goes when it is full or at the finish, never part-filled.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The bytes a stream's frames carry, read through as they arrive: no frame
/// is held, whole or in part.
struct FrameReader<R> {
    source: R,
    /// The current frame's bytes not yet read.
    left: usize,
    /// Whether the end frame has been read.
    ended: bool,
}

impl<R: Read> FrameReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            left: 0,
            ended: false,
        }
    }

    /// Reads the next frame's length: the end frame's is 0.
    fn next_frame(&mut self) -> io::Result<()> {
        let mut header = [0; FRAME_HEADER_BYTES];
        self.source.read_exact(&mut header)?;
        let length = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
        if length > MAX_CHUNK_SYNC_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk-sync frame past its bound",
            ));
        }
        self.left = length;
        self.ended = length == 0;
        Ok(())
    }

    /// Ends the stream once its value is read: the value ended where a frame
    /// did, the end frame follows it, and nothing follows that.
    fn finish(mut self) -> io::Result<()> {
        let trailing = || io::Error::new(io::ErrorKind::InvalidData, "chunk-sync stream runs on");
        if !self.ended {
            if self.left > 0 {
                return Err(trailing());
            }
            self.next_frame()?;
            if !self.ended {
                return Err(trailing());
            }
        }
        let mut after = [0; 1];
        match self.source.read(&mut after)? {
            0 => Ok(()),
            _ => Err(trailing()),
        }
    }
}

impl<R: Read> Read for FrameReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.left == 0 {
            if self.ended {
                return Ok(0);
            }
            self.next_frame()?;
        }
        let wanted = output.len().min(self.left);
        let count = self.source.read(&mut output[..wanted])?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= count;
        Ok(count)
    }
}
