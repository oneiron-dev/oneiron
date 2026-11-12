//! Moved from `crates/oneiron/src/dreamer_wake/sieve/policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer sieve policy row".into())
}
