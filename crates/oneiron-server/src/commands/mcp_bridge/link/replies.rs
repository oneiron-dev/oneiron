//! Reply forwarding on the bridge's shared socket driver.

use std::collections::HashMap;

use serde::Deserialize;
use tokio::sync::mpsc;

use super::{Inbound, RPC_ANSWER_ENVELOPE_BYTES};

pub(super) struct ReplyWaiter {
    pub(super) chunks: mpsc::UnboundedSender<Inbound>,
    pub(super) sent: usize,
    pub(super) max_reply_bytes: usize,
}

/// One frame from the server, to the request it answers.
pub(super) fn route(data: &[u8], waiting: &mut HashMap<u64, ReplyWaiter>) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Envelope<P> {
        #[serde(rename = "type")]
        kind: String,
        id: u64,
        last: bool,
        payload: P,
    }
    fn decode<P: serde::de::DeserializeOwned>(envelope: &[u8]) -> Result<Envelope<P>, String> {
        rmp_serde::from_slice(envelope)
            .map_err(|_| "the server sent the MCP socket an undecodable frame".to_owned())
    }
    let Some((&oneiron::sync::transport::TAG_RPC, envelope)) = data.split_first() else {
        return Err("the server sent the MCP socket a frame that is not an app RPC".to_owned());
    };
    let head: Envelope<serde::de::IgnoredAny> = decode(envelope)?;
    match head.kind.as_str() {
        "rpc.res" => {
            let chunk: Envelope<serde_bytes::ByteBuf> = decode(envelope)?;
            let mut finished = chunk.last;
            if let Some(waiter) = waiting.get_mut(&chunk.id)
                && waiter.sent
                    <= waiter
                        .max_reply_bytes
                        .saturating_add(RPC_ANSWER_ENVELOPE_BYTES)
            {
                waiter.sent = waiter.sent.saturating_add(chunk.payload.len());
                finished |= waiter
                    .chunks
                    .send(Inbound::Chunk {
                        bytes: chunk.payload.into_vec(),
                        last: chunk.last,
                    })
                    .is_err();
            }
            // FIFO already contains the chunk that makes the receiver return
            // TooLarge. Later bytes cannot change that outcome; retaining them
            // would let a starved receiver accumulate the rest of the stream.
            if finished {
                waiting.remove(&chunk.id);
            }
        }
        "rpc.err" => {
            let refusal: Envelope<serde_json::Value> = decode(envelope)?;
            if let Some(waiter) = waiting.remove(&refusal.id) {
                let _ = waiter.chunks.send(Inbound::Closed(format!(
                    "the server refused the call on the MCP socket: {}",
                    refusal.payload
                )));
            }
        }
        // A ping's echo, or anything newer this bridge does not read.
        _ => {}
    }
    Ok(())
}

pub(super) struct ReplyChunks {
    chunks: std::vec::IntoIter<Vec<u8>>,
    current: Option<std::io::Cursor<Vec<u8>>>,
}

impl ReplyChunks {
    pub(super) fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into_iter(),
            current: None,
        }
    }
}

impl std::io::Read for ReplyChunks {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(cursor) = self.current.as_mut() {
                let n = std::io::Read::read(cursor, buf)?;
                if n != 0 {
                    return Ok(n);
                }
                self.current = None;
            }
            self.current = Some(std::io::Cursor::new(match self.chunks.next() {
                Some(chunk) => chunk,
                None => return Ok(0),
            }));
        }
    }
}
