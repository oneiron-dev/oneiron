//! Shared ownership of one existing held-job memory lease.

use super::FloorRefusal;

/// A lease shared by one caller and the native buffers it allocated. Growth
/// happens outside writers; native callbacks only assign existing pending room.
/// Physical frees may run on another thread while growth waits. Implementations
/// must not keep an account lock across that wait which those frees also need.
pub trait SharedFloorLease: Send + Sync {
    /// Grows on the same line, counting all prior pending reservations.
    fn grow_pending_untimed(
        &self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal>;

    /// Holds at least this much unassigned pending room. Concurrent physical
    /// frees may satisfy it on the same account without another reservation.
    fn reserve_pending_untimed(
        &self,
        bytes: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal>;

    /// Assigns already admitted pending room to one malloc, without waiting for
    /// capacity, allocating a ticket or joining the floor's wait queue.
    fn try_reserve_pending(&self, bytes: u64) -> bool;

    /// One assigned malloc succeeded, naming its exact allocation.
    fn materialized_reserved(&self, bytes: u64);

    /// One assigned malloc failed without allocating anything.
    fn cancel_reserved(&self, bytes: u64);

    /// Ordinary non-native allocation on the same job, excluding room already
    /// assigned to a native malloc which has not yet completed.
    fn materialized(&self, reserved: u64, actual: u64);

    /// Returns scratch/rollback room, pending first; never takes an assignment
    /// belonging to an in-flight native malloc.
    fn shrink(&self, bytes: u64);

    /// A native allocation has physically freed. Retains its admission for
    /// replay until finish; after finish returns it to the machine line.
    fn reclaimed(&self, bytes: u64);

    /// Returns specific physically freed caller allocations, leaving native
    /// pending room intact. Cached native buffers remain charged separately.
    fn release_allocated(&self, bytes: u64);

    /// Ends the native writer/replay scope. Unused pending room is returned
    /// now; actual cached buffers keep their charge until physical free.
    /// Call after growth waits and the writer return; do not grow afterward.
    /// Physical buffer frees may still run concurrently.
    fn finish(&self);
}
