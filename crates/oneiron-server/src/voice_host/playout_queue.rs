//! Frames waiting for the voice wire, spoken audio gated per chunk (FIX 9542).
//! Entry: PlayoutOutbox::next_current_chunk.
//!
//! A spoken frame is split into chunks under the wire's frame size, and each
//! chunk keeps the live audience gate of the generation that spoke it: the
//! serve loop asks it again right before the chunk is written, after every
//! wait, so a stop, a newcomer's wake or a session end between two chunks
//! keeps every later chunk of that generation off the wire. Frames that are
//! not audio (a control's parts, a receipt) carry no gate and are never
//! dropped with a stopped generation's audio, nor is a later generation's.

use std::collections::VecDeque;

use super::speech::{PlayoutFrame, PlayoutGate};
use super::wire;

/// One wire frame's share of a spoken frame: whole PCM16LE samples as
/// STANDARD base64, with the gate of the generation that spoke it.
pub(super) struct QueuedPlayoutChunk {
    pub(super) generation: u64,
    pub(super) sample_rate: u32,
    pub(super) data: String,
    gate: PlayoutGate,
}

impl QueuedPlayoutChunk {
    /// Whether its generation still plays to the live audience. Ask right
    /// before the chunk is written.
    pub(super) fn is_current(&self) -> bool {
        self.gate.is_current()
    }
}

/// One item waiting for the wire.
pub(super) enum Queued<F> {
    /// Spoken audio, gated.
    Pcm(QueuedPlayoutChunk),
    /// A frame that is not audio: never gated, never dropped.
    Frame(F),
}

/// What waits for the wire, in order.
pub(super) struct PlayoutOutbox<F> {
    queue: VecDeque<Queued<F>>,
}

impl<F> PlayoutOutbox<F> {
    pub(super) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Queues `frame`'s audio as chunks under the wire's frame size, each
    /// with its generation's gate. A frame whose generation no longer plays
    /// queues nothing.
    pub(super) fn push_spoken(&mut self, frame: &PlayoutFrame) {
        let Some((pcm, gate)) = frame.public_parts() else {
            return;
        };
        let generation = pcm.generation.value();
        for data in wire::pcm_chunks(pcm) {
            self.queue.push_back(Queued::Pcm(QueuedPlayoutChunk {
                generation,
                sample_rate: pcm.sample_rate,
                data,
                gate: gate.clone(),
            }));
        }
    }

    /// Queues frames that are not audio behind what already waits.
    pub(super) fn push_frames(&mut self, frames: impl IntoIterator<Item = F>) {
        self.queue.extend(frames.into_iter().map(Queued::Frame));
    }

    /// Queues frames that are not audio ahead of what already waits: a
    /// control that came while audio was queued goes before the next chunk.
    pub(super) fn push_frames_first(&mut self, frames: Vec<F>) {
        for frame in frames.into_iter().rev() {
            self.queue.push_front(Queued::Frame(frame));
        }
    }

    /// The next item to write: a frame as queued, or a spoken chunk while its
    /// generation still plays. A chunk whose generation stopped is dropped,
    /// and so is every chunk of that generation queued right behind it; a
    /// frame or another generation's chunk is never dropped with them.
    pub(super) fn next_current_chunk(&mut self) -> Option<Queued<F>> {
        while let Some(next) = self.queue.pop_front() {
            let Queued::Pcm(chunk) = next else {
                return Some(next);
            };
            if chunk.is_current() {
                return Some(Queued::Pcm(chunk));
            }
            while let Some(Queued::Pcm(behind)) = self.queue.front()
                && behind.generation == chunk.generation
            {
                self.queue.pop_front();
            }
        }
        None
    }
}
