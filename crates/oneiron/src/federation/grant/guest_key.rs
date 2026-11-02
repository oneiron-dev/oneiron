//! The guest payload's `holder_key` (FIX-LIST 1978): the public key the
//! guest generated on their own device, as the ask that minted the guest
//! grant carried it, so the owner's slip mint binds it. Only a payload whose
//! ask carried a key holds the entry; every other body encodes exactly as
//! before.

use rmpv::Value;

use super::FederationGrantGuestPayload;
use crate::error::Result;
use crate::federation::codec::invalid_grant;

const KEY_HOLDER_KEY: &str = "holder_key";

/// The payload entry of the guest's key, when it carries one: 64 lowercase
/// hex.
pub(super) fn entry(guest: &FederationGrantGuestPayload) -> Option<(Value, Value)> {
    guest.holder_key.map(|key| {
        (
            Value::from(KEY_HOLDER_KEY),
            Value::from(crate::entity_id::bytes_to_hex_lower(&key)),
        )
    })
}

/// `entries` without the guest's key, and that key. A key that is not 64
/// lowercase hex, or named twice, refuses the body.
pub(super) fn split(entries: &[(Value, Value)]) -> Result<(Vec<(Value, Value)>, Option<[u8; 32]>)> {
    let mut rest = Vec::with_capacity(entries.len());
    let mut holder_key = None;
    for (key, value) in entries {
        if key.as_str() != Some(KEY_HOLDER_KEY) {
            rest.push((key.clone(), value.clone()));
            continue;
        }
        if holder_key.is_some() {
            return Err(invalid_grant());
        }
        holder_key = Some(decode_key(value.as_str().ok_or_else(invalid_grant)?)?);
    }
    Ok((rest, holder_key))
}

fn decode_key(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(invalid_grant());
    }
    let mut key = [0_u8; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid_grant())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid_grant())?;
    }
    Ok(key)
}
