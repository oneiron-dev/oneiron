// Licensed under the Apache License, Version 2.0 or the MIT license.

use std::collections::TryReserveError;

/// Failure while creating an allocation with caller-owned admission.
#[derive(Debug)]
pub enum ReserveError<E> {
    /// The caller refused the requested or actual allocation extent.
    Refused(E),
    /// The allocation does not fit the native capacity representation.
    CapacityOverflow,
    /// The native allocator could not reserve the backing.
    Allocation(TryReserveError),
}
