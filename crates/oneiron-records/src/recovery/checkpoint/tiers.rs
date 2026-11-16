//! Moved from `crates/oneiron/src/recovery/checkpoint/tiers.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Host orders and the host-only log (OF-470 C2): a restore carries them from
/// the live vault, never from an image (`host_holds`).
pub const HOST_HOLD_PREFIX: &[u8] = b"legal_hold:host:";
