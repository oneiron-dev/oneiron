//! The release check a sync client runs on each outgoing frame (FIX 8861),
//! for the integration test of a federation lane's saved document UPDATE
//! whose row turns stale before it leaves (VOICE-PHONE-AGENT-REACH R1,
//! REACH-READ-DOOR-TESTS = A).

use crate::sync::SyncClient;

/// Whether `client` withholds the outgoing `frame` now, as its send path
/// judges each frame right before release: the device-only destination
/// check, and on a federation lane the peer's read of that text.
#[must_use]
pub fn frame_withheld(client: &SyncClient, frame: &[u8]) -> bool {
    client.frame_withheld(frame)
}
