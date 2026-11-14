//! Moved from `crates/oneiron/src/dreamer_runner/program/authority.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

pub const SCOPE_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-scope:v1";

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid turn program binding".into())
}

/// A writer check's refusal is a lapse of the authority, not a failure to
/// judge it.
pub fn lapsed(error: Error) -> Result<bool> {
    match error {
        Error::Claim(_) | Error::InvalidClaimBody(_) => Ok(false),
        error => Err(error),
    }
}
