//! The open organ protocol (ARCH-0075 section 9, `docengine:organ-host`).
//!
//! An organ is its own process. The engine reaches it over one Unix socket:
//! MessagePack messages, each one or more length-prefixed frames, with blob
//! bytes passed as read-only shared-memory descriptors rather than copied. The engine keeps custody and
//! every write; an organ only proposes. This crate depends on nothing in the
//! engine, so a third-party organ can link it, or implement the same frames
//! in any language from the design page.
//!
//! - [`wire`] types: the messages, typed bodies, locators, errors, and the
//!   asks; protocol 2.0.
//! - [`Value`]: a MessagePack value of any depth, and [`codec`], the
//!   protocol's own encoder and decoder, neither of which recurses over a
//!   value's depth.
//! - `frame`: framing and descriptor passing (Unix).
//! - `region`: sealed read-only regions (Unix).
//! - `runtime`: the organ side, [`serve`] and the [`Organ`] trait (Unix).
//! - [`seal`]: the seal organ's revision classification, which its verdicts
//!   carry to the engine.
//! - [`memory`]: the `memory.grow` ask, an organ's own buffers reserved
//!   before it allocates them.

pub mod codec;
pub mod memory;
pub mod seal;
mod value;
pub mod wire;

#[cfg(unix)]
mod frame;
#[cfg(unix)]
mod region;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
pub mod spin;

pub use codec::{
    CodecError, TYPED_DEPTH, encoded_len, from_slice, from_value, read_cost, to_value, to_vec,
};

pub use memory::{ASK_MEMORY_GROW, MemoryAnswer, MemoryAsk};

#[cfg(unix)]
pub use frame::{
    FrameBooking, FrameError, frame_body_len, frame_read_cost, recv_frame, recv_frame_polled,
    recv_frame_polled_booked, recv_frame_until, recv_frame_until_booked, recv_handshake,
    recv_handshake_until_booked, send_frame, send_frame_if, send_frame_until,
};
#[cfg(unix)]
pub use region::{MappedRegion, SharedRegion};
#[cfg(unix)]
pub use runtime::{
    Answer, AnswerMemory, AskBytes, AskReply, Asker, CallContext, InputBytes, Organ, OutputBytes,
    VERB_ECHO, VERB_TOUCH, serve, serve_stream, touch_fold,
};
pub use serde_bytes::ByteBuf;
pub use wire::*;
