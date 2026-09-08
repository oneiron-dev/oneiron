//! Storage key builders, key length guards, and field validators.
use std::time::{SystemTime, UNIX_EPOCH};

use super::codec::UsageError;

const USAGE_EVENT_PREFIX: &str = "usage:event:";

pub(super) const USAGE_TENANT_ROLLUP_PREFIX: &str = "usage:rollup:tenant:";

pub(super) const USAGE_VAULT_ROLLUP_PREFIX: &str = "usage:rollup:vault:";

const CONSUMER_ALLOWANCE_PREFIX: &str = "consumer:allowance:";

pub(super) const CONSUMER_TOP_UP_PREFIX: &str = "consumer:top-up:";

pub(super) const MAX_SYNC_STATE_KEY_LEN: usize = 511;

pub(super) const MAX_DIMENSION_LEN: usize = 256;

pub(super) const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;

pub(super) fn usage_event_key(tenant_id: &str, vault_id: &str, idempotency_key: &str) -> String {
    format!(
        "{USAGE_EVENT_PREFIX}{}:{}:{}",
        key_part(tenant_id),
        key_part(vault_id),
        key_part(idempotency_key)
    )
}

pub(super) fn tenant_rollup_key(tenant_id: &str) -> String {
    format!("{USAGE_TENANT_ROLLUP_PREFIX}{}", key_part(tenant_id))
}

pub(super) fn vault_rollup_key(tenant_id: &str, vault_id: &str) -> String {
    format!(
        "{USAGE_VAULT_ROLLUP_PREFIX}{}:{}",
        key_part(tenant_id),
        key_part(vault_id)
    )
}

pub(super) fn consumer_allowance_key(tenant_id: &str) -> String {
    format!("{CONSUMER_ALLOWANCE_PREFIX}{}", key_part(tenant_id))
}

pub(super) fn consumer_top_up_key(tenant_id: &str, idempotency_key: &str) -> String {
    format!(
        "{CONSUMER_TOP_UP_PREFIX}{}:{}",
        key_part(tenant_id),
        key_part(idempotency_key)
    )
}

pub(super) fn validate_consumer_top_up_storage_keys(
    tenant_id: &str,
    idempotency_key: &str,
) -> Result<(), UsageError> {
    validate_consumer_usage_storage_keys(tenant_id, None)?;
    validate_sync_state_key_len(
        "idempotencyKey",
        consumer_top_up_key_len(tenant_id, idempotency_key),
    )?;
    Ok(())
}

pub(super) fn validate_consumer_usage_storage_keys(
    tenant_id: &str,
    vault_id: Option<&str>,
) -> Result<(), UsageError> {
    validate_sync_state_key_len("tenantId", consumer_allowance_key_len(tenant_id))?;
    validate_sync_state_key_len("tenantId", tenant_rollup_key_len(tenant_id))?;
    if let Some(vault_id) = vault_id {
        validate_sync_state_key_len("vaultId", vault_rollup_key_len(tenant_id, vault_id))?;
    }
    Ok(())
}

fn validate_sync_state_key_len(field: &'static str, key_len: usize) -> Result<(), UsageError> {
    if key_len > MAX_SYNC_STATE_KEY_LEN {
        return Err(UsageError::InvalidField {
            field,
            message: "produces a storage key that is too long",
        });
    }
    Ok(())
}

pub(super) fn tenant_rollup_key_len(tenant_id: &str) -> usize {
    USAGE_TENANT_ROLLUP_PREFIX.len() + key_part_len(tenant_id)
}

pub(super) fn vault_rollup_key_len(tenant_id: &str, vault_id: &str) -> usize {
    USAGE_VAULT_ROLLUP_PREFIX.len() + key_part_len(tenant_id) + 1 + key_part_len(vault_id)
}

pub(super) fn consumer_allowance_key_len(tenant_id: &str) -> usize {
    CONSUMER_ALLOWANCE_PREFIX.len() + key_part_len(tenant_id)
}

pub(super) fn consumer_top_up_key_len(tenant_id: &str, idempotency_key: &str) -> usize {
    CONSUMER_TOP_UP_PREFIX.len() + key_part_len(tenant_id) + 1 + key_part_len(idempotency_key)
}

pub(super) fn key_part_len(value: &str) -> usize {
    value.len() * 2
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

pub(super) fn validate_non_negative_finite(
    field: &'static str,
    value: f64,
) -> Result<(), UsageError> {
    if !value.is_finite() {
        return Err(UsageError::InvalidField {
            field,
            message: "must be finite",
        });
    }
    if value < 0.0 {
        return Err(UsageError::InvalidField {
            field,
            message: "must not be negative",
        });
    }
    Ok(())
}

pub(super) fn validate_positive_finite(field: &'static str, value: f64) -> Result<(), UsageError> {
    validate_non_negative_finite(field, value)?;
    if value == 0.0 {
        return Err(UsageError::InvalidField {
            field,
            message: "must be greater than zero",
        });
    }
    Ok(())
}

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
