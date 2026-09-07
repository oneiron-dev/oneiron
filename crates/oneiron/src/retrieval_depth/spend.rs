//! Failure-side usage for the bounded deep retrieval and composition calls.

use crate::Error;

/// A retrieval result that preserves reported backend usage even on failure.
pub type RetrievalResult<T> = std::result::Result<T, RetrievalError>;

/// A failed operation and the actual backend tokens it consumed.
///
/// A backend reports only THIS call's spend, including a failed call that
/// consumed tokens before producing an error. The depth executor adds earlier
/// calls with saturating arithmetic, so its error carries the whole read's
/// spend. Hosts must settle that total before returning the error. This is
/// usage, not a reservation or a cap; do not count earlier calls twice.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct RetrievalError {
    /// The original failure, retained for the caller's existing error mapping.
    #[source]
    pub error: Error,
    /// Actual reported tokens, bounded to `u64` like successful usage totals.
    pub tokens_used: u64,
}

impl From<Error> for RetrievalError {
    /// For failures that consumed no backend tokens. A backend that spent
    /// tokens must construct `RetrievalError` with that usage explicitly.
    fn from(error: Error) -> Self {
        Self {
            error,
            tokens_used: 0,
        }
    }
}
