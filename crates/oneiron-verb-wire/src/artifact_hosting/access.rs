//! Moved from `crates/oneiron/src/artifact_hosting/access.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::artifact_hosting::*;

pub fn link_digest(token: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("oneiron artifact link token v1", token)
}
