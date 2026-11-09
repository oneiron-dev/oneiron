//! Moved from `crates/oneiron/src/dreamer_runner/types.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

/// Why a Dreamer attempt parked. The reason text is for people; this is
/// what code reads. Only a [`Self::ProviderUnavailable`] park resumes when a
/// model offer recovers (OF-305).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerParkCause {
    /// Its model call failed because the provider is down: a server error,
    /// a timeout, a cut stream or an empty answer.
    ProviderUnavailable,
    /// Its executor returned an error or panicked.
    ExecutorError,
    /// The wake pass hit its deadline and the attempt kept its progress.
    Checkpoint,
    /// A refusal or error park: resumed as the same try, like Checkpoint,
    /// once its retry delay has passed.
    Retry,
    /// The host's pause (a managed reap freeze, FIX 6909) stopped the pass
    /// before the attempt dispatched: resumed like Checkpoint.
    Paused,
    /// The pass was cancelled.
    Cancelled,
    /// It waits on a signal: a budget approval, a seat login, a peer.
    Signal,
    /// Anything else: a missing route, a refused config, a failed step only
    /// an owner act clears.
    Other,
}

impl DreamerParkCause {
    /// Stable string stored in the private parked row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ExecutorError => "executor_error",
            Self::Checkpoint => "checkpoint",
            Self::Retry => "retry",
            Self::Paused => "paused",
            Self::Cancelled => "cancelled",
            Self::Signal => "signal",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "provider_unavailable" => Some(Self::ProviderUnavailable),
            "executor_error" => Some(Self::ExecutorError),
            "checkpoint" => Some(Self::Checkpoint),
            "retry" => Some(Self::Retry),
            "paused" => Some(Self::Paused),
            "cancelled" => Some(Self::Cancelled),
            "signal" => Some(Self::Signal),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}
pub mod retry_policy;
