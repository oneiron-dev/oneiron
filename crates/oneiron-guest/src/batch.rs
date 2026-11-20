//! The batch transcript channel a vendor's sandbox runs the guest over (L8-43,
//! VENDOR-BOUNDARY = A: a batch boundary).
//!
//! A vendor's machine has no live channel to the host, so the host's opening
//! frames (start, component, the staged workspace files, ready) arrive as one
//! file, and every frame the guest sends is appended to another. The host
//! replays that transcript through its own checks once the run ends. Each
//! frame the guest waits on a receipt for is answered here, as the host
//! answers it when nothing is wrong: proposals and output frames are taken,
//! and every credential read is refused, because no broker is reachable from
//! the vendor's machine. The host's replay answers each one again and refuses
//! the whole run where its answer differs, so this channel never widens what
//! a run may do.
use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::protocol::MAX_FRAME;

/// The guest frames that wait for a receipt, and the receipt each takes.
fn receipt_for(frame_type: &str) -> Option<bool> {
    match frame_type {
        "write_open" | "write_chunk" | "write_close" | "delete" | "rename" | "output_text"
        | "output_bytes" | "store_bytes" => Some(true),
        // No channel to the credential broker exists on a vendor's machine.
        "credential_read" => Some(false),
        _ => None,
    }
}

/// One encoded host frame: its length, then its JSON.
fn encode(value: &serde_json::Value) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Reads the host's opening from `input`, appends every guest frame to
/// `output`, and answers each receipt wait from `receipts`.
pub(crate) struct TranscriptChannel<R, W> {
    input: R,
    output: W,
    /// Bytes of guest frames not yet complete.
    pending: Vec<u8>,
    /// Encoded receipts the guest has yet to read.
    receipts: VecDeque<u8>,
}

impl<R: Read, W: Write> TranscriptChannel<R, W> {
    pub(crate) fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            pending: Vec::new(),
            receipts: VecDeque::new(),
        }
    }

    /// Queues the receipt of every complete guest frame in `pending`.
    fn answer_complete_frames(&mut self) -> io::Result<()> {
        loop {
            let Some(header) = self.pending.first_chunk::<4>() else {
                return Ok(());
            };
            let len = u32::from_be_bytes(*header) as usize;
            if len == 0 || len > MAX_FRAME {
                return Err(io::Error::other("guest frame size"));
            }
            if self.pending.len() < 4 + len {
                return Ok(());
            }
            let frame: serde_json::Value =
                serde_json::from_slice(&self.pending[4..4 + len]).map_err(io::Error::other)?;
            self.pending.drain(..4 + len);
            let frame_type = frame["type"]
                .as_str()
                .ok_or_else(|| io::Error::other("guest frame without a type"))?;
            if let Some(accepted) = receipt_for(frame_type) {
                self.receipts.extend(encode(
                    &serde_json::json!({ "type": "receipt", "accepted": accepted }),
                )?);
            }
        }
    }
}

impl<R: Read, W: Write> Read for TranscriptChannel<R, W> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.receipts.is_empty() {
            return self.input.read(bytes);
        }
        let mut read = 0;
        while read < bytes.len() {
            let Some(byte) = self.receipts.pop_front() else {
                break;
            };
            bytes[read] = byte;
            read += 1;
        }
        Ok(read)
    }
}

impl<R: Read, W: Write> Write for TranscriptChannel<R, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.write_all(bytes)?;
        self.pending.extend_from_slice(bytes);
        self.answer_complete_frames()?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn frame(value: &Value) -> Vec<u8> {
        encode(value).expect("encode")
    }

    fn read_frame(channel: &mut impl Read) -> Value {
        let mut header = [0; 4];
        channel.read_exact(&mut header).expect("header");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        channel.read_exact(&mut body).expect("body");
        serde_json::from_slice(&body).expect("JSON")
    }

    #[test]
    fn batch_channel_answers_each_wait_and_refuses_credential_reads() {
        let opening = frame(&json!({"type": "ready"}));
        let mut channel = TranscriptChannel::new(io::Cursor::new(opening), Vec::new());
        assert_eq!(read_frame(&mut channel), json!({"type": "ready"}));

        for (sent, accepted) in [
            (
                json!({"type": "write_open", "path": "/mnt/workspace/a"}),
                true,
            ),
            (json!({"type": "write_chunk", "bytes": [1, 2]}), true),
            (json!({"type": "write_close"}), true),
            (json!({"type": "delete", "path": "/mnt/workspace/b"}), true),
            (
                json!({"type": "rename", "from": "/mnt/workspace/c", "to": "/mnt/workspace/d"}),
                true,
            ),
            (
                json!({"type": "output_text", "target": "console", "start": true, "frame": "x"}),
                true,
            ),
            (
                json!({"type": "credential_read", "handle": "h", "operation": "get", "scheme": "https", "host": "example.com"}),
                false,
            ),
        ] {
            // A frame written in two parts, as the session writes it, takes one receipt.
            let bytes = frame(&sent);
            channel.write_all(&bytes[..4]).expect("header");
            assert!(
                channel.receipts.is_empty(),
                "no receipt before the frame is whole"
            );
            channel.write_all(&bytes[4..]).expect("body");
            assert_eq!(
                read_frame(&mut channel),
                json!({"type": "receipt", "accepted": accepted}),
                "{sent}"
            );
        }

        for sent in [
            json!({"type": "step_result", "result_json": "{}"}),
            json!({"type": "finish", "status": 0}),
        ] {
            channel.write_all(&frame(&sent)).expect("frame");
        }
        assert!(
            channel.receipts.is_empty(),
            "a result and a finish wait on nothing"
        );
        let mut rest = Vec::new();
        assert_eq!(
            channel.read_to_end(&mut rest).expect("end"),
            0,
            "the opening is spent"
        );

        let mut transcript = io::Cursor::new(channel.output);
        let types: Vec<Value> = std::iter::from_fn(|| {
            (transcript.position() < transcript.get_ref().len() as u64)
                .then(|| read_frame(&mut transcript)["type"].clone())
        })
        .collect();
        assert_eq!(
            types,
            [
                "write_open",
                "write_chunk",
                "write_close",
                "delete",
                "rename",
                "output_text",
                "credential_read",
                "step_result",
                "finish"
            ]
            .map(Value::from),
            "the transcript holds the guest's frames, never a receipt"
        );
    }

    #[test]
    fn batch_channel_refuses_a_frame_over_the_bound() {
        let mut channel = TranscriptChannel::new(io::empty(), Vec::new());
        let over = u32::try_from(MAX_FRAME + 1).expect("bound").to_be_bytes();
        assert!(channel.write_all(&over).is_err());
    }
}
