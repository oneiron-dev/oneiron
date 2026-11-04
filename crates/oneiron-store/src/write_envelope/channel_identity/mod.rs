//! Channel-identity claim predicates and pinned wire keys.

pub mod keys;

use keys::CHANNEL_IDENTITY_CLAIM_PREDICATES;

/// Returns whether `predicate` belongs to the ChannelIdentity claim family.
#[must_use]
pub fn is_channel_identity_claim_predicate(predicate: &str) -> bool {
    CHANNEL_IDENTITY_CLAIM_PREDICATES.contains(&predicate)
}
