//! Owner/vault keys and validation for the durable meter queue.
use super::codec::UsageError;
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) const MAX_DIMENSION_LEN: usize = 256;
pub(super) const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
/// What every stored usage event's key starts with, before its billing
/// owner's, vault's and idempotency key's parts.
pub(super) const USAGE_EVENT_ROOT: &str = "usage:event:";
pub(super) fn usage_event_prefix(owner: &str, vault: &str) -> String {
    format!("{USAGE_EVENT_ROOT}{}:{}:", key_part(owner), key_part(vault))
}
pub(super) fn usage_event_key(owner: &str, vault: &str, id: &str) -> String {
    usage_event_prefix(owner, vault) + &key_part(id)
}
/// A stored event key's owner and vault parts, as [`usage_event_key`]
/// encoded them, beside the rest of the key: `None` for a key with no two
/// parts after [`USAGE_EVENT_ROOT`].
pub(super) fn usage_event_parts(key: &str) -> Option<(&str, &str, &str)> {
    let (owner, rest) = key.strip_prefix(USAGE_EVENT_ROOT)?.split_once(':')?;
    let (vault, id) = rest.split_once(':')?;
    Some((owner, vault, id))
}
/// `vault` as its part of a stored event's key.
pub(super) fn vault_key_part(vault: &str) -> String {
    key_part(vault)
}
/// The value a key part encodes, when it is one [`key_part`] made.
pub(super) fn decoded_key_part(part: &str) -> Option<String> {
    if !part.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..part.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(part.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok()
}
pub(super) fn vault_rollup_key(owner: &str, vault: &str) -> String {
    vault_rollup_key_of_parts(&key_part(owner), &key_part(vault))
}
/// [`vault_rollup_key`] for the owner and vault parts of a stored event's key.
pub(super) fn vault_rollup_key_of_parts(owner: &str, vault: &str) -> String {
    format!("usage:rollup:vault:{owner}:{vault}")
}
/// The key a meter row of `metric` is kept under (FIX 7764). Its last part
/// is the digest of the idempotency key, so a key that repeats the owner and
/// vault (a storage day's) still fits; the stored row keeps the whole key.
pub(super) fn meter_key(owner: &str, vault: &str, metric: &str, id: &str) -> String {
    format!(
        "usage:meter:{}:{}:{metric}:{}",
        key_part(owner),
        key_part(vault),
        blake3::hash(id.as_bytes()).to_hex()
    )
}
/// The key of one owner/vault/metric/day meter rollup (FIX 7764).
pub(super) fn meter_rollup_key(owner: &str, vault: &str, metric: &str, period: u64) -> String {
    format!(
        "usage:meter-rollup:{}:{}:{metric}:{period:020}",
        key_part(owner),
        key_part(vault)
    )
}
pub(super) fn usage_repair_receipt_key(id: &str) -> String {
    format!("usage:repair:receipt:{id}")
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
