//! What can go wrong on the engine side of an organ call.

use std::time::Duration;

use oneiron_organ_protocol::{FrameError, OrganError};

/// Why an installed organ cannot take calls right now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unavailable {
    /// Its install grant was withdrawn.
    Revoked,
    /// It crashed five times in ten minutes; reinstall to clear.
    Quarantined,
    /// Its binary failed the handshake; the reason says how.
    Incompatible(String),
    /// A third-party organ, and this platform has no filesystem confinement
    /// for organs yet. Fail closed.
    ThirdPartyUnconfined,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    #[error("organ {0} is not installed")]
    NotInstalled(String),
    #[error("organ {organ} is unavailable: {reason:?}")]
    Unavailable { organ: String, reason: Unavailable },
    #[error("organ {organ} is backing off after a crash; retry in {retry_after:?}")]
    Backoff {
        organ: String,
        retry_after: Duration,
    },
    #[error("organ {organ} does not offer {verb} at schema {schema}")]
    UnknownVerb {
        organ: String,
        verb: String,
        schema: u32,
    },
    #[error("organ handshake refused: {0}")]
    Handshake(String),
    #[error("organ {0} crashed")]
    Crashed(String),
    #[error("organ call missed its deadline")]
    DeadlineExceeded,
    #[error("organ call was revoked")]
    Revoked,
    #[error("the organ budget could not admit the call before its deadline")]
    BudgetTimeout,
    #[error("the call asks more than the whole organ budget")]
    OverBudget,
    #[error("a call carries at most 16 inputs")]
    TooManyInputs,
    #[error("organ reply broke a protocol rule: {0}")]
    ReplyInvalid(String),
    #[error("input {artifact} v{version} not found")]
    InputNotFound { artifact: String, version: u64 },
    #[error("input media type {0} is not in the organ's grant")]
    MediaTypeNotGranted(String),
    #[error(transparent)]
    Organ(#[from] OrganError),
    #[error(transparent)]
    Engine(#[from] oneiron::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("organ io: {0}")]
    Io(#[from] std::io::Error),
}
