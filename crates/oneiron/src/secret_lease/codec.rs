//! Strict msgpack key-map idiom plus the three row body codecs.

use std::path::PathBuf;

use rmpv::Value;

use super::types::{
    LocalRegistration, SECRET_LEASE_KEY_PREFIX, SECRET_LOCAL_REGISTRATION_PREFIX,
    SECRET_MATERIALIZATION_RECEIPT_KIND, SECRET_MATERIALIZATION_RECEIPT_PREFIX, SecretLease,
    SecretLeaseStatus, SecretMaterializationReceipt, StoredLocalRegistration,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::CustodyTier;

// ---------------------------------------------------------------------------
// Row keys
// ---------------------------------------------------------------------------

pub(super) fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidSecretLeaseBody(reason)
}

pub(super) fn lease_key(lease_id: &EntityId) -> Vec<u8> {
    format!("{SECRET_LEASE_KEY_PREFIX}{}", lease_id.to_hex()).into_bytes()
}

pub(super) fn receipt_key(receipt_id: &EntityId) -> Vec<u8> {
    format!(
        "{SECRET_MATERIALIZATION_RECEIPT_PREFIX}{}",
        receipt_id.to_hex()
    )
    .into_bytes()
}

pub(super) fn registration_key(lease_id: &EntityId) -> Vec<u8> {
    format!("{SECRET_LOCAL_REGISTRATION_PREFIX}{}", lease_id.to_hex()).into_bytes()
}

// ---------------------------------------------------------------------------
// Body codecs (MessagePack key maps — the secret_custody.rs idiom)
// ---------------------------------------------------------------------------

/// Reads a required key out of a MessagePack map's entries. A MISSING or
/// DUPLICATED key both yield `None` — the call site turns that into the
/// typed body reject; an ambiguous body is never defaulted.
pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
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

pub(super) fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

pub(super) fn entity_id_at(
    entries: &[(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<EntityId> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::from_hex(s).ok())
        .ok_or(invalid_body(reason))
}

pub(super) fn u64_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<u64> {
    required_value(entries, key)
        .and_then(as_u64)
        .ok_or(invalid_body(reason))
}

pub(super) fn string_at(
    entries: &[(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<String> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(invalid_body(reason))
}

pub(super) fn tier_at(
    entries: &[(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<CustodyTier> {
    let n = u64_at(entries, key, reason)?;
    CustodyTier::from_u8(u8::try_from(n).map_err(|_| invalid_body(reason))?)
        .ok_or(invalid_body(reason))
}

/// Decodes a MessagePack key-map body, rejecting non-map bodies and
/// trailing bytes. Shared shape for the three row codecs.
pub(super) fn decode_map_body(bytes: &[u8], reason: &'static str) -> Result<Vec<(Value, Value)>> {
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

pub(super) fn encode_map_body(pairs: Vec<(&str, Value)>) -> Result<Vec<u8>> {
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
const SECRET_LEASE_BODY_KEYS: [&str; 9] = [
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

pub(super) fn encode_secret_lease_body(lease: &SecretLease) -> Result<Vec<u8>> {
    encode_map_body(vec![
        (
            SECRET_LEASE_BODY_KEYS[0],
            Value::from(lease.lease_id.to_hex()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[1],
            Value::from(lease.secret_ref.as_str()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[2],
            Value::from(lease.binding_effector.as_str()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[3],
            Value::from(u64::from(lease.tier.as_u8())),
        ),
        (SECRET_LEASE_BODY_KEYS[4], Value::from(lease.granted_at)),
        (SECRET_LEASE_BODY_KEYS[5], Value::from(lease.expires_at)),
        (
            SECRET_LEASE_BODY_KEYS[6],
            Value::from(u64::from(lease.status.as_wire_byte())),
        ),
        (
            SECRET_LEASE_BODY_KEYS[7],
            Value::from(lease.materialization_receipt.to_hex()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[8],
            Value::from(u64::from(lease.value_generation)),
        ),
    ])
}

pub(crate) fn decode_secret_lease_body(bytes: &[u8]) -> Result<SecretLease> {
    let entries = decode_map_body(bytes, "secret lease body must be a map")?;
    let status_raw = u64_at(&entries, SECRET_LEASE_BODY_KEYS[6], "lease status")?;
    Ok(SecretLease {
        lease_id: entity_id_at(&entries, SECRET_LEASE_BODY_KEYS[0], "lease lease_id")?,
        secret_ref: string_at(&entries, SECRET_LEASE_BODY_KEYS[1], "lease secret_ref")?,
        binding_effector: string_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[2],
            "lease binding_effector",
        )?,
        tier: tier_at(&entries, SECRET_LEASE_BODY_KEYS[3], "lease tier")?,
        granted_at: u64_at(&entries, SECRET_LEASE_BODY_KEYS[4], "lease granted_at")?,
        expires_at: u64_at(&entries, SECRET_LEASE_BODY_KEYS[5], "lease expires_at")?,
        status: SecretLeaseStatus::from_wire_byte(
            u8::try_from(status_raw).map_err(|_| invalid_body("lease status"))?,
        )
        .ok_or(invalid_body("lease status"))?,
        materialization_receipt: entity_id_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[7],
            "lease materialization_receipt",
        )?,
        value_generation: u32::try_from(u64_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[8],
            "lease value_generation",
        )?)
        .map_err(|_| invalid_body("lease value_generation"))?,
    })
}

/// The materialization receipt body's MessagePack keys (`kind` first).
const SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS: [&str; 8] = [
    "kind",
    "receipt_id",
    "secret_ref",
    "effector",
    "tier",
    "lease_id",
    "materialized_at",
    "value_generation",
];

pub(super) fn encode_materialization_receipt_body(
    receipt: &SecretMaterializationReceipt,
) -> Result<Vec<u8>> {
    encode_map_body(vec![
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[0],
            Value::from(SECRET_MATERIALIZATION_RECEIPT_KIND),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[1],
            Value::from(receipt.receipt_id.to_hex()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[2],
            Value::from(receipt.secret_ref.as_str()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[3],
            Value::from(receipt.effector.as_str()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[4],
            Value::from(u64::from(receipt.tier.as_u8())),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[5],
            Value::from(receipt.lease_id.to_hex()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[6],
            Value::from(receipt.materialized_at),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[7],
            Value::from(u64::from(receipt.value_generation)),
        ),
    ])
}

/// Decodes a materialization-receipt body. Test-only today: the row's
/// consumer surface (CSTDY-02/SECRET-04) lands on later stack layers and
/// can ungate this when it needs it.
#[cfg(test)]
pub(super) fn decode_materialization_receipt_body(
    bytes: &[u8],
) -> Result<SecretMaterializationReceipt> {
    let entries = decode_map_body(bytes, "materialization receipt body must be a map")?;
    let kind = string_at(
        &entries,
        SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[0],
        "receipt kind",
    )?;
    if kind != SECRET_MATERIALIZATION_RECEIPT_KIND {
        return Err(invalid_body("receipt kind"));
    }
    Ok(SecretMaterializationReceipt {
        receipt_id: entity_id_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[1],
            "receipt receipt_id",
        )?,
        secret_ref: string_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[2],
            "receipt secret_ref",
        )?,
        effector: string_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[3],
            "receipt effector",
        )?,
        tier: tier_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[4],
            "receipt tier",
        )?,
        lease_id: entity_id_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[5],
            "receipt lease_id",
        )?,
        materialized_at: u64_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[6],
            "receipt materialized_at",
        )?,
        value_generation: u32::try_from(u64_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[7],
            "receipt value_generation",
        )?)
        .map_err(|_| invalid_body("receipt value_generation"))?,
    })
}

/// The local-registration body's MessagePack keys. `removal_error` and
/// `removal_attempted_at` are the teardown record: both `Nil` while the
/// registration is live.
const SECRET_LOCAL_REGISTRATION_BODY_KEYS: [&str; 6] = [
    "lease_id",
    "path",
    "content_hash",
    "project_id",
    "removal_error",
    "removal_attempted_at",
];

pub(super) fn encode_local_registration_body(stored: &StoredLocalRegistration) -> Result<Vec<u8>> {
    let registration = &stored.registration;
    encode_map_body(vec![
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[0],
            Value::from(registration.lease_id.to_hex()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[1],
            Value::from(registration.path.to_string_lossy().as_ref()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[2],
            Value::Binary(registration.content_hash.to_vec()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[3],
            Value::from(registration.project_id.as_str()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[4],
            match &stored.removal_error {
                Some(error) => Value::from(error.as_str()),
                None => Value::Nil,
            },
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[5],
            match stored.removal_attempted_at {
                Some(at) => Value::from(at),
                None => Value::Nil,
            },
        ),
    ])
}

/// Decodes a local-registration body. `pub(crate)` so SECRET-03
/// (ONE-1921) assembles its exclusion set from these rows without a codec
/// fork.
pub(crate) fn decode_local_registration_body(bytes: &[u8]) -> Result<StoredLocalRegistration> {
    let entries = decode_map_body(bytes, "secret local registration body must be a map")?;
    let content_hash: [u8; 32] =
        match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[2]) {
            Some(Value::Binary(bytes)) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid_body("registration content_hash"))?,
            _ => return Err(invalid_body("registration content_hash")),
        };
    let removal_error = match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[4]) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(invalid_body("registration removal_error"))?,
        ),
    };
    let removal_attempted_at =
        match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[5]) {
            Some(Value::Nil) | None => None,
            Some(value) => Some(as_u64(value).ok_or(invalid_body("registration removal_at"))?),
        };
    Ok(StoredLocalRegistration {
        registration: LocalRegistration {
            lease_id: entity_id_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[0],
                "registration lease_id",
            )?,
            path: PathBuf::from(string_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[1],
                "registration path",
            )?),
            content_hash,
            project_id: string_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[3],
                "registration project_id",
            )?,
        },
        removal_error,
        removal_attempted_at,
    })
}
