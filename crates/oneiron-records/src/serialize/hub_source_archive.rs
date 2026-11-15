//! Moved from `crates/oneiron/src/serialize/hub_source_archive.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("hub source archive: {reason}"))
}
