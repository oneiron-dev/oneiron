//! K-proof door for the extraction read digests that main already sends: the equality
//! tokens, the facts pin and the policy pin.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

/// The identity, topic, value and slice equality tokens, in that order, each over its own
/// encoded key bytes.
#[must_use]
pub fn equality_tokens(identity: &[u8], topic: &[u8], value: &[u8], slice: &[u8]) -> [String; 4] {
    crate::snapshot_read::tokens_of_encoded_keys_for_test(identity, topic, value, slice)
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
