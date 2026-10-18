//! Typed stale-federation metadata returned only for admitted recall items.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStaleStamp {
    /// None when the terminal fold is visible before the stamp sweep ran.
    pub stale_since: Option<u64>,
    pub age_secs: Option<u64>,
    pub reason: String,
    pub pact_epoch: u64,
}

impl MemoryStaleStamp {
    pub(super) fn from_stamp(stamp: crate::federation::WorldStaleStamp, now: u64) -> Self {
        let since = (stamp.stamped_at_secs != 0).then_some(stamp.stamped_at_secs);
        Self {
            stale_since: since,
            age_secs: since.map(|since| now.saturating_sub(since)),
            reason: stamp.reason.as_str().to_owned(),
            pact_epoch: stamp.disconnect_epoch,
        }
    }
}
