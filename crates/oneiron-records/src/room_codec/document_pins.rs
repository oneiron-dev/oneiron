//! Moved from `crates/oneiron/src/room_codec/document_pins.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroMap;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("document pin refused: {reason}"))
}
