//! Moved from `crates/oneiron/src/sync/federation_burst/queue.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkKind {
    Selector,
    MemberUpdate,
    GuestUpdate,
}
