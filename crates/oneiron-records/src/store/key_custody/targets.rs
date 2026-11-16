//! Moved from `crates/oneiron/src/store/key_custody/targets.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;

pub const WIRE_VERSION: u8 = 1;

pub fn journal_corrupt() -> Error {
    Error::CorruptedIndex("key custody acknowledgement journal")
}
