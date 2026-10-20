//! The host's memory floor, as a browser session's live-handle registry
//! meets it (C013). The host decides the budget; the driver only asks it
//! before the registry grows and tells it once the registry shrinks.

/// One session's charge on the host's retained-memory floor for its
/// live-handle registry. Dropping it gives the bytes back.
pub trait HandleRetention: Send {
    /// Moves the charge to `bytes` in all. Shrinking always succeeds;
    /// growth the floor will not admit answers `false` and leaves the
    /// charge as it was.
    fn resize(&mut self, bytes: usize) -> bool;
}
