//! Moved from `crates/oneiron/src/inbox/list.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What [`Memory::inbox_mark`] records for its caller. Acknowledging also
/// marks seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMark {
    Seen,
    Acked,
}
