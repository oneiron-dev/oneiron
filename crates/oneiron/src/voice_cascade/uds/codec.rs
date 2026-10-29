//! Voice UDS frame codec.
//! Entry: read_frame.
//! Request and Response are owned here; RetrievalContext by voice_cascade.

use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Shutdown;
use crate::Vault;
use crate::voice_cascade::RetrievalContext;
use crate::voice_cascade::spilled_audio::{AudioSpool, SpilledFrame};

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

/// One frame, however long its newline takes: past the spool's inline
/// bound it waits spilled, not in memory (FIX 3728), and is read back
/// whole at its newline. The timeouts still close a frame that never
/// ends.
pub(super) fn read_frame(
    reader: &mut impl BufRead,
    shutdown: &Shutdown,
    spool: &AudioSpool,
    vault: &Vault,
) -> io::Result<Frame> {
    let mut frame = SpilledFrame::new();
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
        // A spill that fails after it opened ends the frame like a
        // timeout does: the peer gets one error, not a bare close.
        if frame.append(spool, &bytes[..count]).is_err() {
            return Ok(Frame::Fatal("frame_unreadable"));
        }
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            let bytes = match frame.finish(spool, vault) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(Frame::Fatal("frame_unreadable")),
            };
            return Ok(Frame::Data(bytes));
        }
    }
}

pub(super) fn write_response(writer: &mut impl Write, response: &Response) -> io::Result<()> {
    // No entity bodies or host error strings enter this type.
    let mut bytes =
        serde_json::to_vec(response).map_err(|_| io::Error::other("response encoding failed"))?;
    bytes.push(b'\n');
    writer.write_all(&bytes)
}
