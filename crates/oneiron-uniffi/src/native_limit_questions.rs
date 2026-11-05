//! `Oneiron::native_limit_questions`: the engine `[limits]` rows this client's
//! own vault crossed, served from the shared client's host collector.
//!
//! The getter delegates to
//! [`oneiron_remote::OneironClient::native_limit_questions`] and maps each row
//! directly; `None` stays `None` (remote, attached, or rebound view) and
//! `Some` with an empty vector means no row crossed yet. Both counts cross as
//! exact `u64`. The PID gate error propagates through the existing
//! [`OneironError`] conversion.

use crate::{Oneiron, OneironError};

/// One kept engine-row crossing on the SDK client's own vault.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NativeLimitQuestion {
    /// The `[limits]` row key that asked.
    pub row: String,
    /// What the row stood at for the work, exact.
    pub bound: u64,
    /// What the work measured, exact.
    pub measured: u64,
}

#[uniffi::export]
impl Oneiron {
    /// The engine `[limits]` rows this client's own vault crossed, latest per
    /// row: the row's key plus what it stood at and what the work measured,
    /// both exact. `None` on a remote, attached, or rebound view; an empty
    /// list where no row crossed yet.
    pub fn native_limit_questions(&self) -> Result<Option<Vec<NativeLimitQuestion>>, OneironError> {
        let rows = self.inner.native_limit_questions()?;
        Ok(rows.map(|rows| {
            rows.into_iter()
                .map(|row| NativeLimitQuestion {
                    row: row.row.to_owned(),
                    bound: row.bound,
                    measured: row.measured,
                })
                .collect()
        }))
    }
}
