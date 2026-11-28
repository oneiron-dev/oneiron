//! The node file's settings of the disk check (design 7.9; FIX
//! EXEC-NODE-DISK-CHECK-UNBUILT): its period, and the bounds of its payload
//! walk. A payload deeper or with more entries than these is not measured
//! and ends as `DiskLimit`. They decide whether a job that keeps within its
//! disk request still ends, so they are settings with today's recommended
//! defaults (lead 25 Nov 00:04; R3a's remark 22:40).
//!
//! The constants live here, with no tie to the job service (which is
//! Unix-only), so the settings read on every platform (review r13 R13-13 of
//! #10512); `jobs::payload_usage` takes them from here.

/// Default of `payload_depth_max`: the deepest directory the walk enters,
/// counted from the payload directory (its own entries are at level 1).
pub const PAYLOAD_DEPTH_MAX_DEFAULT: u32 = 64;

/// The most `payload_depth_max` may say, and the most any walk enters: the
/// walk holds one open directory per level, inside the job control
/// handler's descriptor limit.
pub const PAYLOAD_DEPTH_MAX_CEILING: u32 = 256;

/// Default of `payload_entries_max`: the most entries the walk counts, the
/// payload directory included.
pub const PAYLOAD_ENTRIES_MAX_DEFAULT: u64 = 1_000_000;

/// The most `disk_check_secs` may say: one hour (review r13 R13-14).
pub const DISK_CHECK_SECS_CEILING: u64 = 3_600;

pub(super) fn payload_entries_max_default() -> u64 {
    PAYLOAD_ENTRIES_MAX_DEFAULT
}
pub(super) fn payload_depth_max_default() -> u32 {
    PAYLOAD_DEPTH_MAX_DEFAULT
}

/// Checks `disk_check_secs` (1 to [`DISK_CHECK_SECS_CEILING`]),
/// `payload_entries_max` (at least 1) and `payload_depth_max` (1 to
/// [`PAYLOAD_DEPTH_MAX_CEILING`]).
///
/// # Errors
///
/// The reason, naming the field.
pub(super) fn check(disk_check_secs: u64, entries_max: u64, depth_max: u32) -> Result<(), String> {
    if disk_check_secs == 0 || disk_check_secs > DISK_CHECK_SECS_CEILING {
        return Err(format!(
            "execution_node.disk_check_secs must be 1 to {DISK_CHECK_SECS_CEILING}"
        ));
    }
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

#[cfg(unix)]
impl super::ExecutionNodeSettings {
    /// The disk check's walk bounds this file sets; the walk's time bound
    /// is the engine's.
    #[must_use]
    pub fn payload_walk_bounds(&self) -> crate::gpu_execution_node::jobs::PayloadWalkBounds {
        crate::gpu_execution_node::jobs::PayloadWalkBounds {
            depth_max: self.payload_depth_max,
            entries_max: self.payload_entries_max,
            ..crate::gpu_execution_node::jobs::PayloadWalkBounds::default()
        }
    }
}
