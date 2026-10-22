//! Booked frames (FIX 6195): room for every allocation a frame makes, made
//! before it is made. The wire is the one [`super`] frames; only when the
//! sides book changes.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{FrameError, Wait, recv_frame_with};

/// What a frame's receiver books for it: room for its body before a byte of
/// the body is read, then room for the value the body decodes into before
/// that is built, and the body's room given back once only the value is
/// left. A booking may wait; what it returns comes back with the frame and
/// holds its room for as long as the value lives.
pub trait FrameBooking {
    /// What holds the frame's room.
    type Held;

    /// Room for the body's declared `len` bytes.
    ///
    /// # Errors
    /// The frame is not wanted, or no room can be made for it.
    fn body(&mut self, len: u32) -> Result<Self::Held, FrameError>;

    /// Room for at most `bytes` more: the value the body decodes into.
    ///
    /// # Errors
    /// As [`Self::body`].
    fn value(&mut self, held: &mut Self::Held, bytes: u64) -> Result<(), FrameError>;

    /// The body's `len` bytes are gone; the value stays.
    fn body_gone(&mut self, held: &mut Self::Held, len: u32);
}

/// A booking of the body alone, as the `_reserved` reads make it.
struct BodyOnly<F>(Option<F>);

impl<L, F: FnOnce(u32) -> Result<L, FrameError>> FrameBooking for BodyOnly<F> {
    type Held = L;

    fn body(&mut self, len: u32) -> Result<L, FrameError> {
        match self.0.take() {
            Some(reserve) => reserve(len),
            None => Err(FrameError::Protocol("a frame's body was booked twice")),
        }
    }

    fn value(&mut self, _: &mut L, _: u64) -> Result<(), FrameError> {
        Ok(())
    }

    fn body_gone(&mut self, _: &mut L, _: u32) {}
}

/// `reserve` as a booking of the body alone.
pub(super) fn body_only<L>(
    reserve: impl FnOnce(u32) -> Result<L, FrameError>,
) -> impl FrameBooking<Held = L> {
    BodyOnly(Some(reserve))
}

/// The bytes `msg`'s frame body encodes to, counted with nothing
/// allocated: what a sender books before it sends the frame (FIX 6195).
///
/// # Errors
/// The message does not encode.
pub fn frame_body_len<T: Serialize>(msg: &T) -> Result<u64, FrameError> {
    struct Count(u64);
    impl io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len() as u64);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    rmp_serde::encode::write_named(&mut count, msg)?;
    Ok(count.0)
}

/// [`super::recv_frame_polled_reserved`], booked: `booking` makes room for
/// the body, then for its value ([`FrameBooking`]).
///
/// # Errors
/// As [`super::recv_frame`], plus whatever `booking` returns.
pub fn recv_frame_polled_booked<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    limit: u32,
    booking: B,
) -> Result<(T, Vec<OwnedFd>, u32, B::Held), FrameError> {
    recv_frame_with(stream, limit, Wait::Poll(None), booking)
}

/// [`super::recv_frame_until_reserved`], booked as
/// [`recv_frame_polled_booked`] books. `deadline` bounds the reads, not the
/// booking's own waits, which should end by it too.
///
/// # Errors
/// As [`super::recv_frame_until`], plus whatever `booking` returns.
pub fn recv_frame_until_booked<T: DeserializeOwned, B: FrameBooking>(
    stream: &UnixStream,
    limit: u32,
    deadline: Option<Instant>,
    booking: B,
) -> Result<(T, Vec<OwnedFd>, u32, B::Held), FrameError> {
    recv_frame_with(stream, limit, Wait::until(deadline), booking)
}
