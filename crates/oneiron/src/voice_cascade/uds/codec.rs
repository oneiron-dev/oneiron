use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::MAX_FRAME_BYTES;
use super::Shutdown;
use crate::voice_cascade::RetrievalContext;

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Open {
        utterance_id: String,
    },
    Partial {
        handle: String,
        revision: u64,
        text: String,
    },
    Final {
        handle: String,
        revision: u64,
        text: String,
    },
    Close {
        handle: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(super) enum Response {
    Opened {
        handle: String,
    },
    Partial {
        decision: &'static str,
        context: Option<RetrievalContext>,
    },
    Final {
        context: RetrievalContext,
    },
    Closed,
    Error {
        code: &'static str,
    },
}

impl Response {
    pub(super) fn error(code: &'static str) -> Self {
        Self::Error { code }
    }
}

pub(super) enum Frame {
    Data(Vec<u8>),
    End,
    Fatal(&'static str),
}

/// Never drain an oversized frame: close instead of waiting for its newline.
pub(super) fn read_frame(reader: &mut impl BufRead, shutdown: &Shutdown) -> io::Result<Frame> {
    let mut frame = Vec::with_capacity(1024);
    let idle_start = Instant::now();
    let mut frame_start = None;
    loop {
        if shutdown.is_requested() {
            return Ok(Frame::End);
        }
        if frame_start.is_some_and(|start: Instant| start.elapsed() >= FRAME_TIMEOUT)
            || (frame_start.is_none() && idle_start.elapsed() >= IDLE_TIMEOUT)
        {
            return Ok(Frame::Fatal("timeout"));
        }
        let bytes = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if bytes.is_empty() {
            return Ok(if frame.is_empty() {
                Frame::End
            } else {
                Frame::Fatal("truncated_frame")
            });
        }
        frame_start.get_or_insert_with(Instant::now);
        let newline = bytes.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
        if count > MAX_FRAME_BYTES - frame.len() {
            return Ok(Frame::Fatal("frame_too_large"));
        }
        frame.extend_from_slice(&bytes[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Frame::Data(frame));
        }
    }
}

pub(super) fn write_response(writer: &mut impl Write, response: &Response) -> io::Result<()> {
    // Ref count and string sizes are bounded before serialization. No entity
    // bodies or host error strings enter this type.
    let mut bytes =
        serde_json::to_vec(response).map_err(|_| io::Error::other("response encoding failed"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::other("response exceeds limit"));
    }
    bytes.push(b'\n');
    writer.write_all(&bytes)
}
