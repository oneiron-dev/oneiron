//! Moved from `crates/oneiron/src/sweep/carrier_facts.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The derive-key context of a copied-id fingerprint.
pub const COPIED_ID_CONTEXT: &str = "oneiron.asset-carrier.scrub-hex.v1";

/// The fingerprint of a 32-byte window when every byte is ASCII hex, read
/// lowercase, as the scrub's copied-id scan reads it.
pub fn copied_id_fingerprint(window: &[u8]) -> Option<[u8; 16]> {
    if window.len() != 32 || !window.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut lower = [0u8; 32];
    for (dst, src) in lower.iter_mut().zip(window) {
        *dst = src.to_ascii_lowercase();
    }
    let hash = blake3::Hasher::new_derive_key(COPIED_ID_CONTEXT)
        .update(&lower)
        .finalize();
    let mut fingerprint = [0u8; 16];
    fingerprint.copy_from_slice(&hash.as_bytes()[..16]);
    Some(fingerprint)
}
