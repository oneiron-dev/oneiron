//! The device PIN's step lock, for integration tests (row OCS-OWNER-PIN):
//! a test of two steps at once reads here that the second one waited for
//! the first, where a pause of fixed length would only assume it.

use crate::world_keys::DevicePin;

/// How many steps of `pin` found another step running and waited for it. A
/// step is a typed PIN's check, a set, a change, a forget, and each
/// enrollment or hold of an owner signing key over `pin`'s keystore.
#[must_use]
pub fn steps_that_waited(pin: &DevicePin) -> u64 {
    pin.steps_that_waited()
}
