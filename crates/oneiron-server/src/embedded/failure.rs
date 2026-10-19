//! Why an embedded engine call failed, by cause (OF-237): the one projection
//! every binding raises, a stable code beside the error's own words.
//!
//! Each cause the engine knows is attached where it is raised, as an
//! [`EngineFailure`] in the error's chain. [`engine_error_kind`] reads it
//! back by type, never from the words; a failure no cause names is
//! [`EngineErrorKind::Internal`].

use std::fmt;

/// One cause of an embedded engine failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EngineErrorKind {
    /// No named cause.
    Internal,
    /// The engine is stopped; `wake` serves it again.
    Stopped,
    /// The engine is closed and refuses every call.
    Closed,
    /// A relay host's config, refused before anything opens.
    RelayRefused,
    /// Called from inside an async runtime or an app host callback.
    WrongThread,
    /// The serve config did not resolve.
    Config,
    /// The vault did not open.
    VaultOpen,
    /// Serving did not start, or ended before the app's `ready`.
    StartFailed,
    /// The connection or its reply ended: closed by the app, ended by the
    /// server, or cut off by a stop.
    ConnectionEnded,
    /// A buffered reply's body is over a buffered request's cap.
    ReplyTooLarge,
    /// A request the engine does not send: a path not in origin form, an
    /// upgrade on a buffered request, or a malformed method or header.
    BadRequest,
}

impl EngineErrorKind {
    /// The stable code a binding raises for this cause.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Internal => oneiron::memory::MEMORY_CODE_INTERNAL,
            Self::Stopped => "ENGINE_STOPPED",
            Self::Closed => "ENGINE_CLOSED",
            Self::RelayRefused => "ENGINE_RELAY_REFUSED",
            Self::WrongThread => "ENGINE_WRONG_THREAD",
            Self::Config => "ENGINE_CONFIG",
            Self::VaultOpen => "ENGINE_VAULT_OPEN",
            Self::StartFailed => "ENGINE_START_FAILED",
            Self::ConnectionEnded => "ENGINE_CONNECTION_ENDED",
            Self::ReplyTooLarge => "ENGINE_REPLY_TOO_LARGE",
            Self::BadRequest => "ENGINE_BAD_REQUEST",
        }
    }

    /// What the caller does next.
    pub const fn suggestion(self) -> &'static str {
        match self {
            Self::Internal => "Check the engine's log for this call.",
            Self::Stopped => "Call wake to serve again, then retry.",
            Self::Closed => "Start a new engine; a closed one refuses every call.",
            Self::RelayRefused => {
                "Run a relay host with `oneiron host relay --config <room.json>`."
            }
            Self::WrongThread => {
                "Call the engine from an app thread, never from an async task or an app host callback."
            }
            Self::Config => "Check the config file and the environment the engine resolves.",
            Self::VaultOpen => {
                "Check the vault path and the app keychain's secrets; another process may own the vault."
            }
            Self::StartFailed => "Check the engine's log; the app's ready never ran.",
            Self::ConnectionEnded => "Open a new connection; after a stop, wake the engine first.",
            Self::ReplyTooLarge => "Open a connection for a large reply; it streams.",
            Self::BadRequest => "Send an origin-form path and open a connection for an upgrade.",
        }
    }
}

/// A cause the engine named, carried in an error's chain.
#[derive(Debug)]
pub struct EngineFailure {
    kind: EngineErrorKind,
    message: String,
}

impl EngineFailure {
    /// The cause.
    pub fn kind(&self) -> EngineErrorKind {
        self.kind
    }
}

impl fmt::Display for EngineFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EngineFailure {}

/// An error of `kind`, in `message`'s words.
pub(super) fn failure(kind: EngineErrorKind, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(cause(kind, message))
}

/// `kind` with `message`, to wrap a lower error as context.
pub(super) fn cause(kind: EngineErrorKind, message: impl Into<String>) -> EngineFailure {
    EngineFailure {
        kind,
        message: message.into(),
    }
}

/// The cause the engine named for `error`: the outermost [`EngineFailure`]
/// in its chain, or [`EngineErrorKind::Internal`] when none is there.
pub fn engine_error_kind(error: &anyhow::Error) -> EngineErrorKind {
    error
        .downcast_ref::<EngineFailure>()
        .or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<EngineFailure>())
        })
        .map_or(EngineErrorKind::Internal, EngineFailure::kind)
}

/// `error` as the one error a served binding raises: its cause's code, the
/// whole chain as its message, and the cause's next step.
pub fn engine_memory_error(error: &anyhow::Error) -> oneiron::MemoryError {
    let kind = engine_error_kind(error);
    oneiron::MemoryError::new(kind.code(), format!("{error:#}"), &[kind.suggestion()])
}
