//! Moved from `crates/oneiron/src/authority/leave_notice_continuity/home_rows.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A delegation's actor content: there is none, as a delegation names no
/// actor.
#[derive(Serialize, Deserialize)]
pub enum NoActorContent {}
