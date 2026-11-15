//! Moved from `crates/oneiron/src/dreamer_runner/free_time/handoff.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time home handoff: {reason}"))
}
pub mod actor_content;
