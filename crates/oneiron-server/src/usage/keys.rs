//! Owner/vault keys and validation for the durable meter queue.
use super::codec::UsageError;
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) const MAX_DIMENSION_LEN: usize = 256;
pub(super) const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
pub(super) fn usage_event_prefix(owner: &str, vault: &str) -> String {
    format!("usage:event:{}:{}:", key_part(owner), key_part(vault))
}
pub(super) fn usage_event_key(owner: &str, vault: &str, id: &str) -> String {
    usage_event_prefix(owner, vault) + &key_part(id)
}
pub(super) fn vault_rollup_key(owner: &str, vault: &str) -> String {
    format!("usage:rollup:vault:{}:{}", key_part(owner), key_part(vault))
}
pub(super) fn validate_key(key: &str) -> Result<(), UsageError> {
    if key.len() > 511 {
        return Err(UsageError::InvalidField {
            field: "owner",
            message: "produces a storage key that is too long",
        });
    }
    Ok(())
}
fn key_part(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn validate_optional_dimension(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), UsageError> {
    if let Some(value) = value {
        validate_dimension(field, value, MAX_DIMENSION_LEN)?;
    }
    Ok(())
}

pub(super) fn validate_dimension(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), UsageError> {
    if value.trim().is_empty() {
        return Err(UsageError::InvalidField {
            field,
            message: "must not be empty",
        });
    }
    if value.len() > max_len {
        return Err(UsageError::InvalidField {
            field,
            message: "is too long",
        });
    }
    Ok(())
}

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
