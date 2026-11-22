//! Door for `tests/fingerprint_keep_booking_dreamer_digests.rs` (PLAN-UC-04 stage 6.2c): the
//! emergency reschedule's instruction, request-to-plan index and item keys, a proactivity
//! digest's locator and content hash, and a free-time policy's digest, which the engine
//! computes in private code.

use crate::EntityId;
use crate::booking::BookingError;
use crate::booking::emergency_reschedule::{EmergencyActionPolicy, EmergencyRescheduleRequest};
use crate::dreamer_runner::maintenance::digest::ProactivityDigest;
use crate::temporal::TimeRange;
use oneiron_records::dreamer_runner::free_time::policy::FreeTimePolicy;

/// An emergency instruction's full raw row key.
///
/// # Errors
/// When the window is inverted, the reason is blank or longer than 4096 bytes, or the
/// fields do not encode.
pub fn instruction_key(
    owner_ref: EntityId,
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
    recorded_at: u64,
) -> Result<Vec<u8>, BookingError> {
    crate::booking::emergency_reschedule::instruction_key_for_test(
        owner_ref,
        window,
        reason,
        action_policy,
        recorded_at,
    )
}

/// The instruction content hash the request-to-plan index is keyed by.
///
/// # Errors
/// As [`instruction_key`].
pub fn request_plan_hash(request: &EmergencyRescheduleRequest) -> Result<[u8; 32], BookingError> {
    crate::booking::emergency_reschedule::request_plan_hash_for_test(request)
}

/// An emergency item's full raw row key, for one event of the request.
///
/// # Errors
/// As [`instruction_key`].
pub fn item_key(
    request: &EmergencyRescheduleRequest,
    event: EntityId,
) -> Result<Vec<u8>, BookingError> {
    crate::booking::emergency_reschedule::item_key(request, event)
}

/// A proactivity digest's locator.
///
/// # Errors
/// When the digest does not encode.
pub fn digest_id(digest: &ProactivityDigest) -> crate::Result<[u8; 32]> {
    crate::dreamer_runner::maintenance::digest::digest_id_for_test(digest)
}

/// A proactivity digest's content hash.
///
/// # Errors
/// When the digest does not encode.
pub fn digest_content_hash(digest: &ProactivityDigest) -> crate::Result<[u8; 32]> {
    crate::dreamer_runner::maintenance::digest::digest_content_hash_for_test(digest)
}

/// A free-time policy's digest, `None` for no policy.
///
/// # Errors
/// When the policy does not encode.
pub fn free_time_policy_digest(policy: Option<&FreeTimePolicy>) -> crate::Result<[u8; 32]> {
    crate::dreamer_runner::free_time_policy_digest_for_test(policy)
}
