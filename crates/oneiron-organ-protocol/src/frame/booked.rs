//! Booked messages (FIX 6195): room for every allocation a message makes,
//! made before it is made. The frames are the ones [`super`] reads; only
//! when the sides book changes.

use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Bound, FrameError, Wait, recv_frame_with};
use crate::codec;
use crate::wire::MAX_FDS_PER_FRAME;

/// Room per received descriptor: the fds-vector capacity, every old+new
/// realloc transient, and the future slots vector, 3x the element (see
/// [`fd_read_cost`]). A cost coefficient, not a cap.
pub const FD_ROOM_PER_FD: u64 = 3 * size_of::<OwnedFd>() as u64;

/// What receiving `count` descriptors takes at its peak: 0 for none, else
/// 3x the element over the count floored at one frame's descriptor capacity
/// ([`MAX_FDS_PER_FRAME`], FIX 12434). The floor covers the first batch's
/// exact reservation before the first extend, so small-N capacity (a `Vec`
/// starts at 4 for its first element) is booked, not grown into; past it,
/// geometric doubling keeps steady capacity under 2N, every old+new
/// realloc transient under 3N, and the later slots collect (`N` exact)
/// under 3N with the fds buffer beside it. Both directions book the same
/// number before their heap grows.
#[must_use]
pub fn fd_read_cost(count: usize) -> u64 {
    if count == 0 {
        0
    } else {
        (count.max(MAX_FDS_PER_FRAME) as u64).saturating_mul(FD_ROOM_PER_FD)
    }
}

/// What a message's receiver books for it: room for each frame's bytes
/// before a byte of the frame is read, then room for the value the message
/// decodes into before that is built, and the bytes' room given back once
/// only the value is left. A booking may wait; what it returns comes back
/// with the message and holds its room for as long as the value lives.
pub trait FrameBooking {
    /// What holds the message's room.
    type Held;

    /// Starts the message's room. The frame reader calls this with zero
    /// before its first header, then books that frame's bytes with
    /// [`Self::more`] once their length is known.
    ///
    /// # Errors
    /// The message is not wanted, or no room can be made for it.
    fn body(&mut self, len: u64) -> Result<Self::Held, FrameError>;

    /// Room for `len` encoded bytes: the first or a further frame of the
    /// same message. By default it grows as [`Self::value`] grows it.
    ///
    /// # Errors
    /// As [`Self::body`].
    fn more(&mut self, held: &mut Self::Held, len: u64) -> Result<(), FrameError> {
        self.value(held, len)
    }

    /// Room for at most `bytes` more: the value the message decodes into.
    ///
    /// # Errors
    /// As [`Self::body`].
    fn value(&mut self, held: &mut Self::Held, bytes: u64) -> Result<(), FrameError>;

    /// Room for `bytes` of descriptor room, made BEFORE the descriptors'
    /// allocation (the fds-vector growth, its realloc transient, the
    /// future slots vector). By default it grows as [`Self::value`] grows
    /// it: correct for all current impls, safe for future ones (a no-op
    /// default would let a future impl silently underbook).
    ///
    /// # Errors
    /// As [`Self::body`].
    fn fds(&mut self, held: &mut Self::Held, bytes: u64) -> Result<(), FrameError> {
        self.value(held, bytes)
    }

    /// A second [`Self::Held`] covering `len` transient realloc-scratch
    /// bytes, on the same floor and budget as the message lease: the old
    /// buffer outliving its realloc. The caller drops it right after the
    /// realloc, so the floor never accumulates it.
    ///
    /// # Errors
    /// As [`Self::body`].
    fn scratch(&mut self, len: u64) -> Result<Self::Held, FrameError>;

    /// The message's `len` encoded bytes are gone; the value stays.
    fn body_gone(&mut self, held: &mut Self::Held, len: u64);
}

/// No booking: the plain reads.
pub(super) struct Unbooked;

impl FrameBooking for Unbooked {
    type Held = ();

    fn body(&mut self, _: u64) -> Result<(), FrameError> {
        Ok(())
    }

    fn value(&mut self, _: &mut (), _: u64) -> Result<(), FrameError> {
        Ok(())
    }

    fn scratch(&mut self, _len: u64) -> Result<(), FrameError> {
        Ok(())
    }

    fn body_gone(&mut self, _: &mut (), _: u64) {}
}

/// The bytes `msg` encodes to, counted with nothing allocated: what a
/// sender books before it sends the message (FIX 6195).
///
/// # Errors
/// The message does not encode.
pub fn frame_body_len<T: Serialize + ?Sized>(msg: &T) -> Result<u64, FrameError> {
    codec::encoded_len(msg).map_err(FrameError::Encode)
}

/// What the receiver of `msg` takes to read it, at its peak: the
/// message's frames and the value they decode into, at once, counted with
/// nothing allocated. A sender reserves it for a receiver that cannot book
/// its own read (FIX 6195).
///
/// # Errors
/// The message does not encode.
pub fn frame_read_cost<T: Serialize + ?Sized>(msg: &T) -> Result<u64, FrameError> {
    codec::read_cost(msg).map_err(FrameError::Encode)
}

/// [`super::recv_frame_polled`], booked: `booking` makes room for each
/// frame, then for the message's value ([`FrameBooking`]). Returns the
/// message's encoded length too.
///
/// # Errors
/// As [`super::recv_frame`], plus whatever `booking` returns.
pub fn recv_frame_polled_booked<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    limit: u32,
    booking: B,
) -> Result<(T, Vec<OwnedFd>, u64, B::Held), FrameError> {
    recv_frame_with(stream, Bound::frames(limit), Wait::Poll(None), booking)
}

/// [`super::recv_frame_until`], booked as [`recv_frame_polled_booked`]
/// books. `deadline` bounds the reads, not the booking's own waits, which
/// should end by it too.
///
/// # Errors
/// As [`super::recv_frame_until`], plus whatever `booking` returns.
pub fn recv_frame_until_booked<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    limit: u32,
    deadline: Option<Instant>,
    booking: B,
) -> Result<(T, Vec<OwnedFd>, u64, B::Held), FrameError> {
    recv_frame_with(stream, Bound::frames(limit), Wait::until(deadline), booking)
}

/// A `hello` or `hello_ack`, booked as [`recv_frame_until_booked`] books,
/// its frames together under the pre-session bound
/// ([`crate::INITIAL_HANDSHAKE_FRAME_BYTES`], FIX 7648).
///
/// # Errors
/// As [`recv_frame_until_booked`]; [`FrameError::TooLarge`] past the bound.
pub fn recv_handshake_until_booked<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    deadline: Option<Instant>,
    booking: B,
) -> Result<(T, Vec<OwnedFd>, u64, B::Held), FrameError> {
    recv_frame_with(stream, Bound::handshake(), Wait::until(deadline), booking)
}

/// A `hello` or `hello_ack`, unbooked and untimed, its frames together
/// under the pre-session bound.
///
/// # Errors
/// As [`super::recv_frame`]; [`FrameError::TooLarge`] past the bound.
pub fn recv_handshake<T: DeserializeOwned>(
    stream: &UnixStream,
) -> Result<(T, Vec<OwnedFd>), FrameError> {
    recv_frame_with(stream, Bound::handshake(), Wait::Syscall, Unbooked)
        .map(|(msg, fds, ..)| (msg, fds))
}
