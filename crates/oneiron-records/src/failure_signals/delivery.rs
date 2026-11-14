//! Moved from `crates/oneiron/src/failure_signals/delivery.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::cell::Cell;

pub const FAILURE_SIGNAL_BATCH_VERSION: u16 = 1;
