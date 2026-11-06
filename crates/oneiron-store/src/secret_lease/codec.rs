//! Strict msgpack key-map idiom plus the three row body codecs.

use std::path::PathBuf;

use rmpv::Value;

use crate::secret_record::types::CustodyTier;
use crate::side_table;
use crate::side_table::codec::RawValue;
use crate::side_table::key::HexId;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::secret_lease::SecretLeaseStatus;

pub fn invalid_body(reason: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretLeaseBody(reason))
}

// ---------------------------------------------------------------------------
// Body codecs (MessagePack key maps — the secret_custody.rs idiom)
// ---------------------------------------------------------------------------

/// Reads a required key out of a MessagePack map's entries. A MISSING or
/// DUPLICATED key both yield `None` — the call site turns that into the
/// typed body reject; an ambiguous body is never defaulted.
pub fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let mut found = None;
    for (k, v) in entries {
        if k.as_str() == Some(key) {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

pub fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

pub fn entity_id_at(
    entries: &[(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<EntityId> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::from_hex(s).ok())
        .ok_or(invalid_body(reason))
}

pub fn u64_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<u64> {
    required_value(entries, key)
        .and_then(as_u64)
        .ok_or(invalid_body(reason))
}

pub fn string_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<String> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(invalid_body(reason))
}

pub fn tier_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<CustodyTier> {
    let n = u64_at(entries, key, reason)?;
    CustodyTier::from_u8(u8::try_from(n).map_err(|_| invalid_body(reason))?)
        .ok_or(invalid_body(reason))
}

/// Decodes a MessagePack key-map body, rejecting non-map bodies and
/// trailing bytes. Shared shape for the three row codecs.
pub fn decode_map_body(bytes: &[u8], reason: &'static str) -> Result<Vec<(Value, Value)>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_body(reason))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret lease row body"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_body(reason));
    };
    Ok(entries)
}

pub fn encode_map_body(pairs: Vec<(&str, Value)>) -> Result<Vec<u8>> {
    let map = Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect(),
    );
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| invalid_body("encode secret lease row body"))?;
    Ok(out)
}

/// The lease body's MessagePack keys, in field order. `9 keys = 9 fields`.
pub const SECRET_LEASE_BODY_KEYS: [&str; 9] = [
    "lease_id",
    "secret_ref",
    "binding_effector",
    "tier",
    "granted_at",
    "expires_at",
    "status",
    "materialization_receipt",
    "value_generation",
];

/// The materialization receipt body's MessagePack keys (`kind` first).
pub const SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS: [&str; 8] = [
    "kind",
    "receipt_id",
    "secret_ref",
    "effector",
    "tier",
    "lease_id",
    "materialized_at",
    "value_generation",
];

/// The local-registration body's MessagePack keys. `removal_error` and
/// `removal_attempted_at` are the teardown record: both `Nil` while the
/// registration is live. `file_dev` and `file_ino` name the file written.
pub const SECRET_LOCAL_REGISTRATION_BODY_KEYS: [&str; 8] = [
    "lease_id",
    "path",
    "content_hash",
    "project_id",
    "removal_error",
    "removal_attempted_at",
    "file_dev",
    "file_ino",
];
