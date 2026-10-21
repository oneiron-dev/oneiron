//! The MLX worker's frame codec (FIX 6755 slice 3, contract rev 3 A2): a
//! 4-byte big-endian length, then that many bytes of UTF-8 JSON, both ways.
//!
//! The 16 MiB bound on one payload lives here and nowhere else: a length
//! over it is refused before a byte is allocated, on a read and on a write.
//! It bounds the codec, never the content: a unit too large for one frame
//! is split across frames by its worker (`super::MlxWorker`). There is no
//! newline framing and no compression, and a frame cut short is never
//! guessed back into step.

use std::io::{ErrorKind, Read, Write};

/// The largest JSON payload one frame carries, its 4-byte length aside.
pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// The length prefix.
const HEADER_BYTES: usize = 4;

/// Why a frame could not be read or written. None carries a byte of the
/// payload.
#[derive(Debug, thiserror::Error)]
pub(super) enum FrameError {
    #[error("the frame is {bytes} bytes, past the codec's {MAX_FRAME_BYTES}")]
    TooLarge { bytes: u64 },
    #[error("the stream ended inside a frame")]
    Truncated,
    #[error("the stream failed: {kind:?}")]
    Io { kind: ErrorKind },
}

impl From<std::io::Error> for FrameError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::UnexpectedEof => Self::Truncated,
            kind => Self::Io { kind },
        }
    }
}

/// Whether a payload of `bytes` fits one frame.
pub(super) const fn fits(bytes: usize) -> bool {
    bytes <= MAX_FRAME_BYTES
}

/// The next frame's payload; `None` when the stream ends cleanly before a
/// header, as a worker's stdout does when it exits. A header or payload cut
/// short is [`FrameError::Truncated`]. The length is checked against the
/// bound before the payload is allocated. A zero-length payload is returned
/// as it is: it is not JSON, which its reader refuses.
pub(super) fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0_u8; HEADER_BYTES];
    let mut filled = 0;
    while filled < HEADER_BYTES {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let length = u32::from_be_bytes(header);
    let bytes = usize::try_from(length).unwrap_or(usize::MAX);
    if !fits(bytes) {
        return Err(FrameError::TooLarge {
            bytes: u64::from(length),
        });
    }
    let mut payload = vec![0_u8; bytes];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Writes `payload` as one frame, whole, and flushes it. A payload past the
/// bound is refused before a byte is written.
pub(super) fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), FrameError> {
    let too_large = || FrameError::TooLarge {
        bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
    };
    if !fits(payload.len()) {
        return Err(too_large());
    }
    let length = u32::try_from(payload.len()).map_err(|_| too_large())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}
