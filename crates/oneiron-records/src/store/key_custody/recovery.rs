//! Moved from `crates/oneiron/src/store/key_custody/recovery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroizing;

pub fn refused(reason: String) -> Error {
    Error::InvalidConfig(reason)
}
