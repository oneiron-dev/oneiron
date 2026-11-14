//! Moved from `crates/oneiron/src/voice_cascade/voxcpm2.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub const MODEL: &str = "VoxCPM2";

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("VoxCPM2: {message}"))
}
