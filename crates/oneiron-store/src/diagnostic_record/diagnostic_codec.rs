//! MessagePack codec and validators for diagnostic event bodies, refs, and tokens.

use std::io::Cursor;

use rmpv::Value;

use crate::diagnostic_record::untrusted_text::is_forbidden_text_scalar;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

pub fn entity_ref_value(entity: &EntityId) -> Value {
    Value::from(entity.to_hex())
}

/// Lowercase-only, so one hash has exactly one spelling on the wire.
pub fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn is_ref_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
}

pub fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'.'
}
