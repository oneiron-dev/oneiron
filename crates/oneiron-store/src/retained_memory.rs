//! Host-owned retained-memory accounting for in-memory storage.

/// The host's charge for one room stretch's memory, reserved on its
/// retained-memory line before the stretch was entered. Dropping it hands
/// its bytes back.
pub trait RetainedCharge: Send + Sync {
    /// Moves the charge to `bytes`, now. It never waits and never refuses:
    /// the memory it stands for is already held.
    fn charge(&self, bytes: usize);
}
