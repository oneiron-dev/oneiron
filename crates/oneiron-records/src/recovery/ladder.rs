//! Moved from `crates/oneiron/src/recovery/ladder.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[cfg(feature = "sync")]
use std::io::Write;

pub const RECOVERY_MANIFEST_ARTIFACT_TYPE: u16 = 2;
