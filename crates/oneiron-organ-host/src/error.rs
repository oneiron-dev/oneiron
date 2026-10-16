//! What can go wrong on the engine side of an organ call.

use std::time::Duration;

#[cfg(unix)]
use oneiron_organ_protocol::FrameError;
use oneiron_organ_protocol::OrganError;

/// Why an installed organ cannot take calls right now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unavailable {
    /// Its install grant was withdrawn.
    Revoked,
    /// A reinstall replaced this install while the call was starting; retry.
    Reinstalled,
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
    /// The organ refused the handshake or broke its protocol: a permanent
    /// incompatibility until reinstall.
    #[error("organ handshake refused: {0}")]
    Handshake(String),
    /// The organ died or stalled before its `hello_ack`: counted as a crash,
    /// so it backs off and may start next time.
    #[error("organ {organ} failed to start: {reason}")]
    StartFailed { organ: String, reason: String },
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
    /// An ask handler tried to call an organ. Nesting could wait on the
    /// outer call's own permit and seat, and a cycle has no depth bound.
    #[error("an ask handler may not call an organ")]
    Reentrant,
    /// The organ asked again after its asks were spent and refused once;
    /// the host cancelled the call.
    #[error("the organ kept asking past its grant's caps")]
    AskBudget,
    #[error(transparent)]
    Organ(#[from] OrganError),
    #[error(transparent)]
    Engine(#[from] oneiron::Error),
    #[cfg(unix)]
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Another of the owner's nodes ran the call and it failed there in a
    /// way this host has no variant for; `detail` is that host's word.
    #[error("organ call on node {machine} failed: {detail}")]
    Remote { machine: String, detail: String },
    #[error("organ io: {0}")]
    Io(#[from] std::io::Error),
}
