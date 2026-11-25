//! The node file's bounds of the disk check's payload walk (design 7.9;
//! FIX EXEC-NODE-DISK-CHECK-UNBUILT): a payload deeper or with more entries
//! than these is not measured and ends as `DiskLimit`. They decide whether a
//! job that keeps within its disk request still ends, so they are settings
//! with today's recommended defaults (lead 25 Nov 00:04; R3a's remark 22:40).

use super::ExecutionNodeSettings;
use crate::gpu_execution_node::jobs::payload_usage::{
    PAYLOAD_DEPTH_MAX_CEILING, PAYLOAD_DEPTH_MAX_DEFAULT, PAYLOAD_ENTRIES_MAX_DEFAULT,
    PayloadWalkBounds,
};

pub(super) fn payload_entries_max_default() -> u64 {
    PAYLOAD_ENTRIES_MAX_DEFAULT
}
pub(super) fn payload_depth_max_default() -> u32 {
    PAYLOAD_DEPTH_MAX_DEFAULT
}

/// Checks `payload_entries_max` (at least 1) and `payload_depth_max` (1 to
/// [`PAYLOAD_DEPTH_MAX_CEILING`]).
///
/// # Errors
///
/// The reason, naming the field.
pub(super) fn check(entries_max: u64, depth_max: u32) -> Result<(), String> {
    if entries_max == 0 {
        return Err("execution_node.payload_entries_max must be at least 1".to_owned());
    }
    if depth_max == 0 || depth_max > PAYLOAD_DEPTH_MAX_CEILING {
        return Err(format!(
            "execution_node.payload_depth_max must be 1 to {PAYLOAD_DEPTH_MAX_CEILING}"
        ));
    }
    Ok(())
}

impl ExecutionNodeSettings {
    /// The disk check's walk bounds this file sets; the walk's time bound
    /// is the engine's.
    #[must_use]
    pub fn payload_walk_bounds(&self) -> PayloadWalkBounds {
        PayloadWalkBounds {
            depth_max: self.payload_depth_max,
            entries_max: self.payload_entries_max,
            ..PayloadWalkBounds::default()
        }
    }
}
