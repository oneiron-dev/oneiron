//! Booked messages (FIX 6195): room for every allocation a message makes,
//! made before it is made. The frames are the ones [`super`] reads; only
//! when the sides book changes.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Bound, FrameError, Wait, recv_frame_with};
use crate::codec;

/// What a message's receiver books for it: room for each frame's bytes
/// before a byte of the frame is read, then room for the value the message
/// decodes into before that is built, and the bytes' room given back once
/// only the value is left. A booking may wait; what it returns comes back
/// with the message and holds its room for as long as the value lives.
pub trait FrameBooking {
    /// What holds the message's room.
    type Held;

    /// Room for the first frame's declared `len` bytes.
    ///
    /// # Errors
    /// The message is not wanted, or no room can be made for it.
    fn body(&mut self, len: u64) -> Result<Self::Held, FrameError>;

    /// Room for `len` more bytes: a further frame of the same message. By
    /// default it grows as [`Self::value`] grows it.
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
