//! Why an embedded engine call failed (OF-237): each call that fails
//! `EngineError` leaves its cause on the calling thread, a stable
//! `OneironEngineErrorCode` and the error's words, for
//! `oneiron_engine_last_error`. The cause is the engine's own
//! (`oneiron_server::embedded::EngineErrorKind`), never read from the words.

use std::cell::RefCell;

use oneiron_server::embedded::{EngineErrorKind, engine_error_kind};

use super::alloc::buffer_from_vec;
use super::guard::{ffi_guard, write_out};
use super::types::{OneironBuffer, OneironStatus};

/// Why the last engine call on this thread failed `EngineError`, read with
/// `oneiron_engine_last_error`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneironEngineErrorCode {
    /// No engine call on this thread has failed `EngineError`.
    None = 0,
    /// No named cause; the message says what failed.
    Internal = 1,
    /// The engine is stopped; `oneiron_engine_wake` serves it again.
    Stopped = 2,
    /// The engine is closed and refuses every call.
    Closed = 3,
    /// A relay host's config, refused before anything opens.
    RelayRefused = 4,
    /// Called from inside an async runtime or an `OneironAppHost` callback.
    WrongThread = 5,
    /// The serve config did not resolve.
    Config = 6,
    /// The vault did not open.
    VaultOpen = 7,
    /// Serving did not start, or ended before `ready`.
    StartFailed = 8,
    /// The connection or its reply ended: closed, ended by the server, or
    /// cut off by a stop.
    ConnectionEnded = 9,
    /// A buffered reply's body is over 64 MiB; open a connection for it.
    ReplyTooLarge = 10,
    /// A request the engine does not send: a path not in origin form, an
    /// upgrade on a buffered request, or a malformed method or header.
    BadRequest = 11,
}

impl From<EngineErrorKind> for OneironEngineErrorCode {
    fn from(kind: EngineErrorKind) -> Self {
        match kind {
            EngineErrorKind::Internal => Self::Internal,
            EngineErrorKind::Stopped => Self::Stopped,
            EngineErrorKind::Closed => Self::Closed,
            EngineErrorKind::RelayRefused => Self::RelayRefused,
            EngineErrorKind::WrongThread => Self::WrongThread,
            EngineErrorKind::Config => Self::Config,
            EngineErrorKind::VaultOpen => Self::VaultOpen,
            EngineErrorKind::StartFailed => Self::StartFailed,
            EngineErrorKind::ConnectionEnded => Self::ConnectionEnded,
            EngineErrorKind::ReplyTooLarge => Self::ReplyTooLarge,
            EngineErrorKind::BadRequest => Self::BadRequest,
        }
    }
}

thread_local! {
    /// The cause and words of the last engine call on this thread that
    /// failed `EngineError`.
    static LAST_ENGINE_ERROR: RefCell<Option<(OneironEngineErrorCode, String)>> =
        const { RefCell::new(None) };
}

/// An engine failure: its cause and words stay on this thread for
/// `oneiron_engine_last_error`, and the call fails `EngineError`.
pub(super) fn engine_failure(error: anyhow::Error) -> OneironStatus {
    let code = OneironEngineErrorCode::from(engine_error_kind(&error));
    let message = format!("{error:#}");
    LAST_ENGINE_ERROR.with(|last| *last.borrow_mut() = Some((code, message)));
    OneironStatus::EngineError
}

/// Read why the last engine call on this thread failed `EngineError`: its
/// stable cause into `out_code` and the error's UTF-8 words into
/// `out_message`, which the caller releases with `oneiron_buffer_free`. With
/// no such failure on this thread, `out_code` is `None` and `out_message`
/// empty. A later failing engine call on this thread replaces it; a call that
/// succeeds or fails with another status leaves it.
///
/// # Safety
///
/// Each non-null out pointer is writable for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_last_error(
    out_code: *mut OneironEngineErrorCode,
    out_message: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_message, OneironBuffer::empty()) {
            return status;
        }
        let (code, message) = LAST_ENGINE_ERROR
            .with(|last| last.borrow().clone())
            .unwrap_or((OneironEngineErrorCode::None, String::new()));
        write_out(out_code, code)
            .and_then(|()| write_out(out_message, buffer_from_vec(message.into_bytes())))
            .map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}
