//! A process's frames, booked before each allocation they make (FIX 6195,
//! 7890): the body of each frame the organ sends before a byte of it is
//! read, then the value it decodes into before that is built, the body's
//! room given back once only the value is left; and each call or answer
//! the host sends before its buffer is made. Each books the budget, and the
//! machine's floor when the host has one. The wire is as it was.

use std::io;
use std::sync::atomic::Ordering;
use std::time::Instant;

use oneiron_organ_protocol::{FrameBooking, FrameError};

use super::Inbox;
use super::lifeline::Lifeline;
use crate::budget::{Lease, Room, Unroomed};
use crate::clock::WaitClock;

/// A frame given no room, as the frame's reader or sender reports it.
pub(super) fn unroomed(refused: Unroomed) -> FrameError {
    match refused {
        Unroomed::Stopped => FrameError::Closed,
        Unroomed::Floor { needed, available } => FrameError::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("the machine's memory floor: {needed} bytes needed, {available} available"),
        )),
    }
}

/// The reader thread's booking of one frame: waited for until the process
/// ends, on the reader's clock, which calls' deadlines do not count.
pub(super) struct Reading<'r> {
    pub(super) inbox: &'r Inbox,
    pub(super) room: &'r Room,
    pub(super) lifeline: &'r Lifeline,
}

impl Reading<'_> {
    fn stopped(&self) -> bool {
        self.lifeline.reaped.load(Ordering::SeqCst) || !self.inbox.alive.load(Ordering::SeqCst)
    }
}

impl FrameBooking for Reading<'_> {
    type Held = Lease;

    fn body(&mut self, len: u32) -> Result<Lease, FrameError> {
        let stopped = || self.stopped();
        self.inbox
            .room
            .timing(|| self.room.lease(u64::from(len), &stopped))
            .map_err(unroomed)
    }

    fn value(&mut self, held: &mut Lease, bytes: u64) -> Result<(), FrameError> {
        let stopped = || self.stopped();
        self.inbox
            .room
            .timing(|| self.room.grow(held, bytes, &stopped))
            .map_err(unroomed)
    }

    fn body_gone(&mut self, held: &mut Lease, len: u32) {
        held.shrink(u64::from(len));
    }
}

/// The handshake's booking of the `hello_ack`: waited for no later than
/// the handshake's deadline, which is checked before each wait and after
/// it too, and no longer than the child lives (FIX 7648, 7890).
pub(super) struct Handshake<'r> {
    pub(super) room: &'r Room,
    pub(super) lifeline: &'r Lifeline,
    pub(super) deadline: Instant,
}

impl Handshake<'_> {
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// What a wait for room came to, as the handshake's deadline judges
    /// it once the wait is over.
    fn settle<T>(&self, booked: Result<T, Unroomed>) -> Result<T, FrameError> {
        match booked {
            Ok(made) if !self.expired() => Ok(made),
            Ok(_) => Err(FrameError::TimedOut),
            Err(Unroomed::Stopped) if self.expired() => Err(FrameError::TimedOut),
            Err(refused) => Err(unroomed(refused)),
        }
    }
}

impl FrameBooking for Handshake<'_> {
    type Held = Lease;

    fn body(&mut self, len: u32) -> Result<Lease, FrameError> {
        if self.expired() {
            return Err(FrameError::TimedOut);
        }
        let stopped = || self.expired() || self.lifeline.exited();
        self.settle(self.room.lease(u64::from(len), &stopped))
    }

    fn value(&mut self, held: &mut Lease, bytes: u64) -> Result<(), FrameError> {
        if self.expired() {
            return Err(FrameError::TimedOut);
        }
        let stopped = || self.expired() || self.lifeline.exited();
        let booked = self.room.grow(held, bytes, &stopped);
        self.settle(booked)
    }

    fn body_gone(&mut self, held: &mut Lease, len: u32) {
        held.shrink(u64::from(len));
    }
}

/// Room for a frame the host is about to send, its encoded body's `len`
/// bytes counted with nothing allocated, booked before the frame takes the
/// writer: the wait is on `waits`, the call's clock, and ends when
/// `stopped` says the frame is not wanted.
pub(super) fn book_send(
    room: &Room,
    waits: &WaitClock,
    len: u64,
    stopped: &dyn Fn() -> bool,
) -> Result<Lease, FrameError> {
    waits
        .timing(|| room.lease(len, stopped))
        .map_err(|refused| match refused {
            Unroomed::Stopped => FrameError::Withdrawn,
            Unroomed::Floor { .. } => unroomed(refused),
        })
}
