//! Door for `tests/fingerprint_keep_release_inquiry_digests.rs` (PLAN-UC-04 stage 6.2d): a
//! publisher training offer's world settings digest and an inquiry's answer effect digest,
//! which the engine computes in private code.

use crate::EntityId;
use crate::Result;
use crate::inquiry::Inquiry;

/// The settings digest of each world and its settings revision, in the order given.
#[must_use]
pub fn training_policy_digest(revisions: &[(EntityId, [u8; 32])]) -> [u8; 32] {
    crate::feedback::training_policy_digest_for_test(revisions)
}

/// The digest of an inquiry's answer effect over `grant`.
///
/// # Errors
/// When the inquiry is invalid or does not encode.
pub fn inquiry_effect_digest(grant: EntityId, inquiry: &Inquiry) -> Result<[u8; 32]> {
    crate::inquiry::effect_digest_for_test(grant, inquiry)
}
