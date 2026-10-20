//! The frame gate between a Lightpanda guest's bytes and its WebSocket
//! (FIX 6851, `oversize_message_policy`). tungstenite cannot go on past a
//! message beyond its bound: it fails, keeping the frame's head, and would
//! hold the whole frame at its next read. So the gate reads each frame's
//! head itself, ahead of it. A data message whose payload passes
//! [`MAX_MESSAGE`] never reaches tungstenite: its frames are discarded as
//! they arrive, and its first [`PREFIX`] bytes are kept and handed back,
//! for its call to fail alone or, as an event, to be dropped. A message
//! sent in frames is held until its last, never past the bound, and goes on
//! whole as one frame of the same payload; once its frames pass the bound
//! it is discarded the same way. Every other frame goes on as it came, and
//! tungstenite judges it by its own bounds, unchanged.
//!
//! The gate starts at the first byte past the upgrade's answer, a frame's
//! head: the upgrade hands tungstenite that answer's head alone, and every
//! byte past it, read with the head or after, goes through the gate.

use crate::cdp::MAX_MESSAGE;
use crate::cdp::overrun::PREFIX;
use std::collections::VecDeque;

/// A frame head's first two bytes, before its extended length and mask key.
const BASE: usize = 2;
/// The last-frame bit and the opcode bits of a head's first byte, and the
/// bit every control opcode sets.
const FIN: u8 = 0x80;
const OPCODE: u8 = 0x0F;
const CONTROL: u8 = 0x08;
/// The mask bit and the short length of a head's second byte.
const MASK: u8 = 0x80;
const LENGTH: u8 = 0x7F;

/// Where the gate stands in the guest's frames.
#[derive(Default)]
pub(super) struct Gate {
    /// The next frame's head, while it is not whole.
    head: Vec<u8>,
    /// The frame whose payload comes now.
    frame: Option<Frame>,
    /// The data message the gate holds or discards.
    message: Option<Held>,
}

/// One frame whose head the gate read.
struct Frame {
    /// Its payload bytes still to come.
    left: u64,
    /// Whether it is a frame of the message the gate holds or discards;
    /// else it goes on as it came.
    held: bool,
    /// Whether it is its message's last.
    fin: bool,
}

/// A data message the gate holds or discards.
struct Held {
    /// Its first frame's first byte: its kind, for the frame it goes on as.
    first: u8,
    /// Its payload so far; once past the bound, only its first [`PREFIX`]
    /// bytes, until they are handed back.
    body: Vec<u8>,
    /// Its payload's size so far.
    size: u64,
    /// Whether its payload passed the bound.
    over: bool,
    /// Whether its first bytes were handed back.
    told: bool,
}

impl Gate {
    /// Takes the guest's next `bytes`: what goes on to tungstenite is added
    /// to `through`, in order. Returns the first bytes of each message that
    /// passed the bound.
    pub(super) fn pass(&mut self, mut bytes: &[u8], through: &mut VecDeque<u8>) -> Vec<Vec<u8>> {
        let mut over = Vec::new();
        loop {
            let Some(frame) = self.frame.as_mut() else {
                let need = head_len(&self.head);
                if self.head.len() >= need {
                    let head = std::mem::take(&mut self.head);
                    self.start(&head, through, &mut over);
                    continue;
                }
                if bytes.is_empty() {
                    break;
                }
                let (part, rest) = bytes.split_at((need - self.head.len()).min(bytes.len()));
                self.head.extend_from_slice(part);
                bytes = rest;
                continue;
            };
            if frame.left == 0 {
                let ends = frame.held && frame.fin;
                self.frame = None;
                if ends {
                    self.finish(through, &mut over);
                }
                continue;
            }
            if bytes.is_empty() {
                break;
            }
            let take =
                usize::try_from(frame.left).map_or(bytes.len(), |left| left.min(bytes.len()));
            let (chunk, rest) = bytes.split_at(take);
            bytes = rest;
            frame.left -= take as u64;
            let held = frame.held;
            if held {
                self.hold(chunk, &mut over);
            } else {
                through.extend(chunk);
            }
        }
        over
    }

    /// Starts the frame whose whole head is `head`.
    fn start(&mut self, head: &[u8], through: &mut VecDeque<u8>, over: &mut Vec<Vec<u8>>) {
        let fin = head[0] & FIN != 0;
        let opcode = head[0] & OPCODE;
        let masked = head[1] & MASK != 0;
        let left = payload_len(head);
        let held = if opcode & CONTROL != 0 {
            // A control frame goes on, even between a held message's frames.
            false
        } else if masked || opcode != 0 {
            // A new message, or a masked frame tungstenite refuses: the
            // message in progress ends.
            self.close(over);
            let gated = !masked && !(fin && left <= MAX_MESSAGE);
            if gated {
                self.message = Some(Held {
                    first: head[0],
                    body: Vec::new(),
                    size: left,
                    over: left > MAX_MESSAGE,
                    told: false,
                });
            }
            gated
        } else if let Some(message) = self.message.as_mut() {
            message.size = message.size.saturating_add(left);
            if !message.over && message.size > MAX_MESSAGE {
                message.over = true;
                message.body.truncate(PREFIX);
                message.body.shrink_to_fit();
            }
            true
        } else {
            // A continuation of no message: tungstenite judges it.
            false
        };
        if !held {
            through.extend(head);
        }
        self.frame = Some(Frame { left, held, fin });
        self.tell(over);
    }

    /// Takes `chunk` of a held frame's payload.
    fn hold(&mut self, chunk: &[u8], over: &mut Vec<Vec<u8>>) {
        let Some(message) = self.message.as_mut() else {
            return;
        };
        if !message.over {
            // Its room grows exactly, at most doubling, never past the
            // bound (its payload so far never passes it).
            let needed = message.body.len() + chunk.len();
            if needed > message.body.capacity() {
                let bound = usize::try_from(MAX_MESSAGE).unwrap_or(usize::MAX);
                let room = message
                    .body
                    .capacity()
                    .saturating_mul(2)
                    .min(bound)
                    .max(needed);
                message.body.reserve_exact(room - message.body.len());
            }
            message.body.extend_from_slice(chunk);
        } else if !message.told {
            let room = PREFIX.saturating_sub(message.body.len()).min(chunk.len());
            message.body.extend_from_slice(&chunk[..room]);
        }
        self.tell(over);
    }

    /// Hands back the first bytes of a message past the bound, once they
    /// came.
    fn tell(&mut self, over: &mut Vec<Vec<u8>>) {
        if let Some(message) = self.message.as_mut()
            && message.over
            && !message.told
            && message.body.len() >= PREFIX
        {
            message.told = true;
            over.push(std::mem::take(&mut message.body));
        }
    }

    /// The held message's last frame came: within the bound it goes on as
    /// one frame of its whole payload; past it, its first bytes are handed
    /// back.
    fn finish(&mut self, through: &mut VecDeque<u8>, over: &mut Vec<Vec<u8>>) {
        let Some(message) = self.message.take() else {
            return;
        };
        if message.over {
            if !message.told {
                over.push(message.body);
            }
            return;
        }
        through.push_back(message.first | FIN);
        let size = message.body.len();
        match (u8::try_from(size), u16::try_from(size)) {
            (Ok(short), _) if short < 126 => through.push_back(short),
            (_, Ok(medium)) => {
                through.push_back(126);
                through.extend(medium.to_be_bytes());
            }
            _ => {
                through.push_back(127);
                through.extend((size as u64).to_be_bytes());
            }
        }
        through.extend(message.body);
    }

    /// Ends the message in progress before its last frame: one past the
    /// bound has its first bytes handed back; one within it is dropped, as
    /// tungstenite refuses a message another frame cuts.
    fn close(&mut self, over: &mut Vec<Vec<u8>>) {
        if let Some(message) = self.message.take()
            && message.over
            && !message.told
        {
            over.push(message.body);
        }
    }
}

/// How long a frame's head is, by its bytes so far: [`BASE`] until its
/// second byte names the room its length and mask key take.
fn head_len(head: &[u8]) -> usize {
    let Some(&second) = head.get(1) else {
        return BASE;
    };
    let length = match second & LENGTH {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if second & MASK == 0 { 0 } else { 4 };
    BASE + length + mask
}

/// A whole head's payload length.
fn payload_len(head: &[u8]) -> u64 {
    match head[1] & LENGTH {
        126 => u64::from(u16::from_be_bytes([head[2], head[3]])),
        127 => {
            let mut length = [0; 8];
            length.copy_from_slice(&head[2..10]);
            u64::from_be_bytes(length)
        }
        short => u64::from(short),
    }
}
