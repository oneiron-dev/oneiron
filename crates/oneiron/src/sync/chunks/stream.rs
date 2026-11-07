//! The chunk-sync stream an HTTP exchange carries each way (FIX 145): an
//! envelope ([`CHUNK_SYNC_VERSION`] and its MessagePack) cut into frames,
//! then an end frame. A frame is its length, a big-endian `u32` from 1 to
//! [`MAX_CHUNK_SYNC_FRAME`], and its bytes; the end frame is a length of 0.
//!
//! Neither side holds a stream whole or refuses one for its length: a writer
//! holds the one frame it fills, and a reader decodes as the frames arrive. A
//! stream that ends before its end frame, or holds anything after it, is no
//! exchange, so a reply cut short reads as a broken transfer, never a shorter
//! one, with no length declared ahead of it.

use std::io::{self, BufReader, Read, Write};

use super::{
    CHUNK_SYNC_VERSION, ChunkSyncRequest, ChunkSyncResponse, MAX_CHUNK_SYNC_FRAME, invalid,
};
use crate::error::Result;

/// The bytes a writer puts in each frame but its last: one stored chunk's
/// most, so a writer holds one such frame at a time.
pub const CHUNK_STREAM_FRAME_BYTES: usize = crate::origin::lfs::LFS_CHUNK_MAX;

/// The bytes a frame's length takes: a big-endian `u32`.
const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();

const _: () = assert!(CHUNK_STREAM_FRAME_BYTES <= MAX_CHUNK_SYNC_FRAME);
const _: () = assert!(MAX_CHUNK_SYNC_FRAME <= u32::MAX as usize);

/// Writes `request` as the stream an HTTP exchange's request carries. Its
/// HAVE and WANT may hold any number of hashes (FIX 8183): no length bounds
/// a stream.
pub fn write_chunk_request_stream(request: &ChunkSyncRequest, sink: impl Write) -> Result<()> {
    write_stream(request, sink)
}

/// Reads one request from the stream an HTTP exchange's request carries,
/// decoded as its frames arrive: no length refuses it, and none of it is
/// held but the request it decodes to.
pub fn read_chunk_request_stream(source: impl Read) -> Result<ChunkSyncRequest> {
    read_stream(source)
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

fn write_stream<T: serde::Serialize>(value: &T, sink: impl Write) -> Result<()> {
    let mut frames = FrameWriter::new(sink);
    frames.write_all(&[CHUNK_SYNC_VERSION])?;
    rmp_serde::encode::write(&mut frames, value).map_err(|_| invalid())?;
    frames.finish()?;
    Ok(())
}

fn read_stream<T: serde::de::DeserializeOwned>(source: impl Read) -> Result<T> {
    let mut frames = FrameReader::new(BufReader::new(source));
    let mut version = [0; 1];
    frames.read_exact(&mut version).map_err(|_| invalid())?;
    if version[0] != CHUNK_SYNC_VERSION {
        return Err(invalid());
    }
    let value =
        T::deserialize(&mut rmp_serde::Deserializer::new(&mut frames)).map_err(|_| invalid())?;
    frames.finish().map_err(|_| invalid())?;
    Ok(value)
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
