//! The frame gate between a Lightpanda guest's bytes and its WebSocket
//! (FIX 6851, FIX 7988). tungstenite cannot go on past a message beyond its
//! bound: it fails, keeping the frame's head, and would hold the whole frame
//! at its next read. So the gate reads each frame's head itself, ahead of
//! it. A message sent in frames, or one frame past [`MAX_MESSAGE`], never
//! reaches tungstenite: the gate holds it until its last frame. Within the
//! framing threshold a held message goes on whole as one frame of the same
//! payload; past it, every byte it holds is charged to the host's memory
//! floor before it is held (`overrun`), and it is handed back whole, in
//! order, for the pipe to route as every message is. Where the floor admits
//! no more of it, it is cut: its first [`PREFIX`] and last `TAIL` bytes
//! are kept, the rest discarded as it arrives, and the cut is handed back
//! once its last frame came. Every other frame goes on as it came, and
//! tungstenite judges it by its own bounds, unchanged.
//!
//! The gate starts at the first byte past the upgrade's answer, a frame's
//! head: the upgrade hands tungstenite that answer's head alone, and every
//! byte past it, read with the head or after, goes through the gate.

use crate::cdp::overrun::{Cut, PREFIX, keep_tail};
use crate::cdp::{MAX_MESSAGE, Pipe};
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
    /// The data message the gate holds or cuts.
    message: Option<Held>,
    /// A message the gate handed back and the pump has not taken yet.
    out: Option<Out>,
}

/// A message the gate hands back to the pump, not to tungstenite.
pub(super) enum Out {
    /// Past the framing threshold, held whole: its payload.
    Whole(Vec<u8>),
    /// Cut where the floor admitted no more of it.
    Cut(Cut),
}

/// One frame whose head the gate read.
struct Frame {
    /// Its payload bytes still to come.
    left: u64,
    /// Whether it is a frame of the message the gate holds or cuts; else
    /// it goes on as it came.
    held: bool,
    /// Whether it is its message's last.
    fin: bool,
}

/// A data message the gate holds or cuts.
struct Held {
    /// Its first frame's first byte: its kind, for the frame it goes on as.
    first: u8,
    /// Its payload so far; once cut, only its first [`PREFIX`] bytes.
    body: Vec<u8>,
    /// Once cut, its last `TAIL` bytes so far.
    tail: Vec<u8>,
    /// Why it was cut, once it was.
    cut: Option<String>,
}

impl Gate {
    /// Takes the guest's next `bytes`: what goes on to tungstenite is added
    /// to `through`, in order. Stops once a message is handed back: how many
    /// of `bytes` it took, and that message, which every byte before it in
    /// `through` comes ahead of.
    pub(super) fn pass(
        &mut self,
        bytes: &[u8],
        through: &mut VecDeque<u8>,
        pipe: &Pipe,
    ) -> (usize, Option<Out>) {
        let mut rest = bytes;
        loop {
            if self.out.is_some() {
                break;
            }
            let Some(frame) = self.frame.as_mut() else {
                let need = head_len(&self.head);
                if self.head.len() >= need {
                    let head = std::mem::take(&mut self.head);
                    self.start(&head, through, pipe);
                    continue;
                }
                if rest.is_empty() {
                    break;
                }
                let (part, after) = rest.split_at((need - self.head.len()).min(rest.len()));
                self.head.extend_from_slice(part);
                rest = after;
                continue;
            };
            if frame.left == 0 {
                let ends = frame.held && frame.fin;
                self.frame = None;
                if ends {
                    self.finish(through);
                }
                continue;
            }
            if rest.is_empty() {
                break;
            }
            let take = usize::try_from(frame.left).map_or(rest.len(), |left| left.min(rest.len()));
            let (chunk, after) = rest.split_at(take);
            rest = after;
            frame.left -= take as u64;
            let held = frame.held;
            if held {
                self.hold(chunk, pipe);
            } else {
                through.extend(chunk);
            }
        }
        (bytes.len() - rest.len(), self.out.take())
    }

    /// Starts the frame whose whole head is `head`.
    fn start(&mut self, head: &[u8], through: &mut VecDeque<u8>, pipe: &Pipe) {
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
            self.close(pipe);
            let gated = !masked && !(fin && left <= MAX_MESSAGE);
            if gated {
                self.message = Some(Held {
                    first: head[0],
                    body: Vec::new(),
                    tail: Vec::new(),
                    cut: None,
                });
            }
            gated
        } else {
            // A continuation of the message held, or of no message, which
            // tungstenite judges.
            self.message.is_some()
        };
        if !held {
            through.extend(head);
        }
        self.frame = Some(Frame { left, held, fin });
    }

    /// Takes `chunk` of a held frame's payload: within the threshold as it
    /// comes; past it, once the floor admitted the room it takes; once cut,
    /// only into its first and last bytes.
    fn hold(&mut self, chunk: &[u8], pipe: &Pipe) {
        let Some(message) = self.message.as_mut() else {
            return;
        };
        if message.cut.is_none() {
            // Its room grows exactly, at most doubling; past the threshold
            // the floor admits it first.
            let needed = message.body.len() + chunk.len();
            if needed > message.body.capacity() {
                let threshold = usize::try_from(MAX_MESSAGE).unwrap_or(usize::MAX);
                let room = message.body.capacity().saturating_mul(2).max(needed);
                let room = if needed <= threshold {
                    room.min(threshold)
                } else {
                    room
                };
                if room > threshold && !pipe.admit_inbound(room) {
                    message.cut = Some(pipe.inbound_refusal());
                    let mut tail = Vec::new();
                    keep_tail(&mut tail, &message.body[message.body.len().min(PREFIX)..]);
                    message.tail = tail;
                    message.body.truncate(PREFIX);
                    message.body.shrink_to_fit();
                    pipe.release_inbound();
                } else {
                    message.body.reserve_exact(room - message.body.len());
                }
            }
        }
        if message.cut.is_none() {
            message.body.extend_from_slice(chunk);
        } else {
            let room = PREFIX.saturating_sub(message.body.len()).min(chunk.len());
            message.body.extend_from_slice(&chunk[..room]);
            keep_tail(&mut message.tail, &chunk[room..]);
        }
    }

    /// The held message's last frame came: within the threshold it goes on
    /// as one frame of its whole payload; past it, it is handed back whole;
    /// cut, its cut is handed back.
    fn finish(&mut self, through: &mut VecDeque<u8>) {
        let Some(message) = self.message.take() else {
            return;
        };
        if let Some(why) = message.cut {
            self.out = Some(Out::Cut(Cut {
                prefix: message.body,
                tail: message.tail,
                why,
            }));
            return;
        }
        let size = message.body.len();
        if u64::try_from(size).map_or(true, |size| size > MAX_MESSAGE) {
            self.out = Some(Out::Whole(message.body));
            return;
        }
        through.push_back(message.first | FIN);
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

    /// Ends the message in progress before its last frame: a cut one has
    /// its cut handed back; one read so far is dropped, as tungstenite
    /// refuses a message another frame cuts, its charge given back.
    fn close(&mut self, pipe: &Pipe) {
        if let Some(message) = self.message.take() {
            match message.cut {
                Some(why) => {
                    self.out = Some(Out::Cut(Cut {
                        prefix: message.body,
                        tail: message.tail,
                        why,
                    }));
                }
                None => pipe.release_inbound(),
            }
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
