//! Moved from `crates/oneiron/src/skill_hub/osv.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub fn token(s: &str, package: bool) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"._+-".contains(&b) || (package && b"/@:".contains(&b))
        })
        && !s.contains("://")
        && !s.contains("..")
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid OSV dependency query or response".into())
}
