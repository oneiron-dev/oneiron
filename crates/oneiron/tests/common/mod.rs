//! Shared fixture helpers for `oneiron` integration tests.
//!
//! Integration binaries cannot see the crate-internal `test_util` module, so
//! the pinned-byte deny-list and the canonical seed helper are mirrored here
//! against the public API. Canonical copy: `src/lib.rs::test_util` — keep the
//! two in sync.
#![allow(dead_code)] // each integration binary uses a subset of these helpers

use oneiron::EntityId;

/// Mirror of `test_util::PINNED_ID_BYTES`; see the canonical doc comment.
pub const PINNED_ID_BYTES: [u8; 13] = [
    0x00, 0x11, 0x42, 0x47, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xD7, 0xE1, 0xFF,
];

/// Canonical test entity id: `[seed; 16]`. Panics on production-pinned seeds,
/// including `entity(0)`. See `test_util::entity` for the full contract.
pub fn entity(seed: u8) -> EntityId {
    assert!(
        !PINNED_ID_BYTES.contains(&seed),
        "test seed {seed:#04x} collides with a production-pinned id byte; \
         pick a byte outside PINNED_ID_BYTES or construct the pinned id explicitly"
    );
    EntityId::from_bytes([seed; 16]).expect("non-pinned seed byte forms a valid entity id")
}
