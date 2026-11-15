//! Moved from `crates/oneiron/src/room_codec/offer_parts.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroMap;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub const MANIFEST: &[u8] = b"\0offer-parts\0";

pub fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("room offer parts refused: {reason}"))
}
