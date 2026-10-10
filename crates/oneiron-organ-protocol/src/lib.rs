//! The open organ protocol (ARCH-0075 section 9, `docengine:organ-host`).
//!
//! An organ is its own process. The engine reaches it over one Unix socket:
//! length-prefixed MessagePack frames, with blob bytes passed as read-only
//! shared-memory descriptors rather than copied. The engine keeps custody and
//! every write; an organ only proposes. This crate depends on nothing in the
//! engine, so a third-party organ can link it, or implement the same frames
//! in any language from the design page.
//!
//! - [`wire`] types: the messages, typed bodies, locators, errors.
//! - `frame`: framing and descriptor passing (Unix).
//! - `region`: sealed read-only regions (Unix).
//! - `runtime`: the organ side, [`serve`] and the [`Organ`] trait (Unix).

pub mod wire;

#[cfg(unix)]
mod frame;
#[cfg(unix)]
mod region;
#[cfg(unix)]
mod runtime;

#[cfg(unix)]
pub use frame::{FrameError, recv_frame, send_frame};
#[cfg(unix)]
pub use region::{MappedRegion, SharedRegion};
#[cfg(unix)]
pub use runtime::{
    Answer, CallContext, InputBytes, Organ, OutputBytes, VERB_ECHO, VERB_TOUCH, serve,
    serve_stream, touch_fold,
};
pub use serde_bytes::ByteBuf;
pub use wire::*;
