//! Moved from `crates/oneiron/src/sync/federation_burst/queue.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkKind {
    Selector,
    MemberUpdate,
    GuestUpdate,
    /// An own device's window update at its home (L7-41).
    DeviceUpdate,
    /// [`Self::DeviceUpdate`] that a residence socket sent to a window it
    /// promoted: its replay judges the update's destination for the device's
    /// machine again, as the socket's own landing does (#9226 review round 2).
    DeviceResidenceUpdate,
}
