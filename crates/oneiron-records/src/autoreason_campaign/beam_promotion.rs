//! Moved from `crates/oneiron/src/autoreason_campaign/beam_promotion.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}
