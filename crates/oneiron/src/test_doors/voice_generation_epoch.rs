//! Doors for oneiron-speech's adapter unit tests (L9-25 PR 3a): a generation
//! token as a cascade session mints one. Only the session mints tokens in
//! the engine; an adapter echoes the token of the request it got.

use crate::voice_cascade::GenerationEpoch;

/// The token of session `session` (a test UUID) at generation `value`.
#[must_use]
pub fn generation_epoch(session: u128, value: u64) -> GenerationEpoch {
    GenerationEpoch::minted_for_test_door(uuid::Uuid::from_u128(session), value)
}
