//! Door for `tests/fingerprint_keep_training_pins.rs` and
//! `tests/training_pin_non_finite.rs` (PLAN-UC-04 stage 6.4a): the training and drafter
//! pins, which the engine takes in private code.

use serde::Serialize;

use crate::Result;

/// The pin a training run's checks take of `value` (its corpus, plan, binding, probe,
/// definition, evaluation and checkpoint pins).
///
/// # Errors
/// [`crate::Error::InvalidConfig`] when `value` has no pin.
pub fn training_pin<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    crate::training_pack::training_pin_for_test(value)
}

/// The pin a drafter version's checks take of `value` (its spec, corpus, load-set and
/// target pins).
///
/// # Errors
/// [`crate::Error::InvalidConfig`] when `value` has no pin.
pub fn drafter_pin<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    crate::drafter::drafter_pin_for_test(value)
}
