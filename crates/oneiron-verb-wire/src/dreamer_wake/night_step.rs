//! Moved from `crates/oneiron/src/dreamer_wake/night_step.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub fn lower_hex_nibble(digit: u8) -> Option<u8> {
    oneiron_hex::nibble(digit)
}
