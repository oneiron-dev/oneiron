//! Moved from `crates/oneiron/src/batch/export/foreign_stage/body_work.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

pub const WORK_VERSION: u8 = 1;

pub const WORK_LABEL: &str = "staged import body work";
