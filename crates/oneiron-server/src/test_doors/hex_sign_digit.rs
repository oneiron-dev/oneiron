//! Doors for `tests/hex_sign_digit_server.rs` (UC-07 PR 7 sign digit): thin calls
//! to the three crate-private hex decoders that moved onto `oneiron-hex`.
//! Compiled only under `--cfg oneiron_test_support`; never API.

/// A managed `--derivation-owner` / `--organization-owner` id, 64 hex, as bytes.
pub fn managed_owner_id_from_hex(value: &str) -> Option<[u8; 32]> {
    crate::managed::decode_hex(value)
}

/// A Slack webhook signature's hex, as bytes.
pub fn webhook_signature_from_hex(text: &str) -> Option<Vec<u8>> {
    crate::builtin_host::decode_hex(text)
}

/// A custody anchor record's hex, as bytes.
pub fn custody_anchor_record_from_hex(text: &str) -> oneiron::Result<Vec<u8>> {
    crate::owner::backup::unhex(text)
}
