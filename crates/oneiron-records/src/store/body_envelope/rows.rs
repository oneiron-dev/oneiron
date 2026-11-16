//! Moved from `crates/oneiron/src/store/body_envelope/rows.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_crypto::SuiteId;

pub const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;

pub const EPOCH: u64 = 1;

pub fn corrupt() -> Error {
    Error::CorruptedIndex("body file key row")
}
