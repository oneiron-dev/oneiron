//! Doors for `tests/hex_sign_digit.rs` (UC-07 PR 7 sign digit): thin calls to the
//! four crate-private hex decoders that moved onto `oneiron-hex`, so the
//! integration test asserts a `+` sign is refused without the crate's own lib
//! test target. Compiled only under `--cfg oneiron_test_support`; never API.

/// A held call's stored approve-once digest, 64 hex, as its 32 bytes.
pub fn connector_call_digest_from_hex(hex: &str) -> Option<[u8; 32]> {
    crate::outbound_consent::digest_from_hex(hex).map(|digest| *digest.as_bytes())
}

/// A kept weave item key, 34 hex, as its 17 native bytes.
pub fn weave_item_key_from_hex(hex: &str) -> Option<[u8; 17]> {
    let mut bytes = [0; 17];
    match crate::claim::WeaveItemKey::from_hex(hex)? {
        crate::claim::WeaveItemKey::Entity(id) => bytes[1..].copy_from_slice(id.as_bytes()),
        crate::claim::WeaveItemKey::LoopDecision(id) => {
            bytes[0] = 1;
            bytes[1..].copy_from_slice(&id.as_bytes());
        }
    }
    Some(bytes)
}

/// An outline evidence pin's hex field, as bytes.
pub fn evidence_pin_unhex(text: &str) -> Option<Vec<u8>> {
    crate::edit_roundtrip::deck_create::unhex(text)
}

/// A retained-carrier reference's hex tail, as bytes.
#[cfg(feature = "sync")]
pub fn federation_burst_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    crate::sync::federation_burst::erase::hex_bytes(hex)
}
