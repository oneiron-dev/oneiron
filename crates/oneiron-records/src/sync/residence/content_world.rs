//! Moved from `crates/oneiron/src/sync/residence/content_world.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use serde::Deserialize;
use serde::Serialize;

/// Tags of the stored witness (`ri:c:`).
pub const EXCLUSIVE: u8 = 1;

pub const BASE: u8 = 2;

pub const SHARED: u8 = 3;
