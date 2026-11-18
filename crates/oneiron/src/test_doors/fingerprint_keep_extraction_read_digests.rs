//! K-proof door for the extraction read digests that main already sends: the equality
//! tokens, the facts pin and the policy pin.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use crate::dreamer_consolidation::routing::CandidateKeys;

/// The identity, topic, value and slice equality tokens of one native key triple, in that
/// order, as the observations read computes them; `None` when the keys do not encode.
#[must_use]
pub fn equality_tokens(keys: &CandidateKeys) -> Option<[String; 4]> {
    crate::snapshot_read::observation_key_tokens_for_test(keys).ok()
}

/// An observations read's facts pin, over the encoded request and fact set.
#[must_use]
pub fn observation_facts_pin(encoded: &[u8]) -> String {
    crate::snapshot_read::pin_of_encoded_facts_for_test(encoded)
}

/// The effective extraction policy's pin, over the encoded policy.
#[must_use]
pub fn extraction_policy_pin(encoded: &[u8]) -> String {
    crate::snapshot_read::pin_of_encoded_policy_for_test(encoded)
}
