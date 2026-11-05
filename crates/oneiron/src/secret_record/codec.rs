//! Core half of `secret_record::codec`: its store-layer items live in `oneiron_store::secret_record::codec` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::secret_record::codec::*;

use super::floor::{as_u64, required_value};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SECRET_CUSTODY_STORED_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus, TierBand,
};
use crate::error::SecretError;
use crate::error::{Error, Result};
use rmpv::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn tier_band_from_value(value: &Value) -> Result<TierBand> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("tier band must be a map"));
    };
    let min = required_value(entries, "min")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("tier band min"))?;
    let max = required_value(entries, "max")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("tier band max"))?;
    Ok(TierBand { min, max })
}

fn floor_from_value(value: &Value) -> Result<SecretCustodyFloor> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("policy_floor_snapshot must be a map"));
    };
    let portable = tier_band_from_value(
        required_value(entries, "portable").ok_or(invalid_body("floor portable"))?,
    )?;
    let device_bound = tier_band_from_value(
        required_value(entries, "device_bound").ok_or(invalid_body("floor device_bound"))?,
    )?;
    let cross_vault = tier_band_from_value(
        required_value(entries, "cross_vault").ok_or(invalid_body("floor cross_vault"))?,
    )?;
    let rotation_max_age_secs = match required_value(entries, "rotation_max_age_secs") {
        Some(Value::Nil) | None => None,
        Some(v) => Some(as_u64(v).ok_or(invalid_body("floor rotation_max_age_secs"))?),
    };
    let mut env_bindings = BTreeMap::new();
    if let Some(Value::Map(rows)) = required_value(entries, "env_bindings") {
        for (k, v) in rows {
            match (k.as_str(), v.as_str()) {
                (Some(k), Some(v)) => {
                    env_bindings.insert(k.to_owned(), v.to_owned());
                }
                _ => return Err(invalid_body("floor env_bindings entry")),
            }
        }
    }
    Ok(SecretCustodyFloor {
        portable,
        device_bound,
        cross_vault,
        rotation_max_age_secs,
        env_bindings,
    })
}

fn binding_from_value(value: &Value) -> Result<SecretBinding> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("binding must be a map"));
    };
    let effector = required_value(entries, "effector")
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("binding effector"))?
        .to_owned();
    let tier_ceiling = required_value(entries, "tier_ceiling")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("binding tier_ceiling"))?;
    let scopes = match required_value(entries, "scopes") {
        Some(Value::Array(items)) => {
            let mut scopes = Vec::with_capacity(items.len());
            for item in items {
                scopes.push(
                    item.as_str()
                        .ok_or(invalid_body("binding scope"))?
                        .to_owned(),
                );
            }
            scopes
        }
        Some(_) => return Err(invalid_body("binding scopes must be an array")),
        None => Vec::new(),
    };
    Ok(SecretBinding {
        effector,
        tier_ceiling,
        scopes,
    })
}

/// Decodes a custody record from its MessagePack key-map body. All 14 keys
/// are required except `rotated_at` (nil-or-int): `bindings`, `manifest_ref`,
/// and `declared_paths` may be EMPTY (an empty array or string is still a
/// present, well-formed key) but must not be MISSING — a record is complete
/// on write. A missing required key is a body-schema reject. The plaintext
/// DTO only: a stored body, whose value is sealed, is refused here and
/// opens through the custody doors (KS-6).
pub fn decode_secret_custody_body(bytes: &[u8]) -> Result<SecretCustodyRecord> {
    let (mut record, value) = decode_custody_map(bytes)?;
    if record.schema_version != SECRET_CUSTODY_SCHEMA_VERSION {
        return Err(invalid_body("unsupported secret custody schema version"));
    }
    let BodyValue::Plain(value) = value else {
        return Err(invalid_body("value_bytes"));
    };
    record.value_bytes = value;
    Ok(record)
}

/// Decodes a custody body's fields, its value slot apart: the record comes
/// back with no value bytes and the schema version the body is stamped
/// with. Exactly one of `value_bytes` and `sealed_value` is present. A key
/// repeated twice is a corrupt body, never an absent one (FIX-LIST 11156):
/// `required_value` reads a duplicated key as missing, so a sealed body
/// hiding a plaintext slot beside it would otherwise decode as sealed.
pub(crate) fn decode_custody_map(bytes: &[u8]) -> Result<(SecretCustodyRecord, BodyValue)> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_body("decode secret custody body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret custody body"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_body("secret custody body must be a map"));
    };
    for (at, (key, _)) in entries.iter().enumerate() {
        if entries[..at].iter().any(|(prior, _)| prior == key) {
            return Err(invalid_body("duplicate secret custody body key"));
        }
    }

    let schema_version = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[0])
        .and_then(as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(invalid_body("schema_version"))?;
    let name = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[1])
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("name"))?
        .to_owned();
    let class = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[2])
        .and_then(|v| v.as_str())
        .and_then(CustodyClass::parse)
        .ok_or(invalid_body("class"))?;
    let device_only = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[3])
        .and_then(Value::as_bool)
        .ok_or(invalid_body("device_only"))?;
    let value = match (
        required_value(&entries, SECRET_CUSTODY_BODY_KEYS[4]),
        required_value(&entries, SECRET_CUSTODY_SEALED_VALUE_KEY),
    ) {
        (Some(Value::Binary(b)), None) => BodyValue::Plain(b.clone()),
        (Some(Value::String(s)), None) => {
            BodyValue::Plain(s.as_str().unwrap_or_default().as_bytes().to_vec())
        }
        (None, Some(Value::Binary(b))) => BodyValue::Sealed(b.clone()),
        _ => return Err(invalid_body("value_bytes")),
    };
    let status = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[5])
        .and_then(|v| v.as_str())
        .and_then(SecretCustodyStatus::parse)
        .ok_or(invalid_body("status"))?;
    let registered_at = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[6])
        .and_then(as_u64)
        .ok_or(invalid_body("registered_at"))?;
    let rotated_at = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[7]) {
        Some(Value::Nil) | None => None,
        Some(v) => Some(as_u64(v).ok_or(invalid_body("rotated_at"))?),
    };
    let rotation_generation = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[8])
        .and_then(as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(invalid_body("rotation_generation"))?;
    // bindings / manifest_ref / declared_paths are REQUIRED keys (FIX5): an
    // empty value is fine, but a MISSING key is a body-schema reject, not a
    // silent empty default.
    let bindings = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[9]) {
        Some(Value::Array(items)) => {
            let mut bindings = Vec::with_capacity(items.len());
            for item in items {
                bindings.push(binding_from_value(item)?);
            }
            bindings
        }
        Some(_) => return Err(invalid_body("bindings must be an array")),
        None => return Err(invalid_body("bindings")),
    };
    let manifest_ref = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[10])
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("manifest_ref"))?
        .to_owned();
    let declared_paths = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[11]) {
        Some(Value::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                paths.push(
                    item.as_str()
                        .ok_or(invalid_body("declared_path"))?
                        .to_owned(),
                );
            }
            paths
        }
        Some(_) => return Err(invalid_body("declared_paths must be an array")),
        None => return Err(invalid_body("declared_paths")),
    };
    let policy_floor_snapshot = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[12]) {
        Some(v) => floor_from_value(v)?,
        None => return Err(invalid_body("policy_floor_snapshot")),
    };

    let model_reveal_allowed = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[13])
        .and_then(Value::as_bool)
        .ok_or(invalid_body("model_reveal_allowed"))?;

    let record = SecretCustodyRecord {
        schema_version,
        name,
        class,
        device_only,
        model_reveal_allowed,
        value_bytes: Vec::new(),
        status,
        registered_at,
        rotated_at,
        rotation_generation,
        bindings,
        manifest_ref,
        declared_paths,
        policy_floor_snapshot,
    };
    Ok((record, value))
}

/// The record a register's protected input holds, value in it, and the
/// manifest text it is framed with, if any; `None` for anything else.
pub(crate) fn decode_register_input(input: &[u8]) -> Option<(SecretCustodyRecord, Option<String>)> {
    let Some(framed) = input.strip_prefix(REGISTER_INPUT_FRAME) else {
        return decode_secret_custody_body(input)
            .ok()
            .map(|record| (record, None));
    };
    let (len, rest) = framed.split_first_chunk::<4>()?;
    let (body, manifest) =
        rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
    let manifest = std::str::from_utf8(manifest).ok()?.to_owned();
    let record = decode_secret_custody_body(body).ok()?;
    Some((record, Some(manifest)))
}

/// The bindings a bind's protected input holds: one array of any count,
/// each naming its own effector of 1 to 256 bytes, with nothing after it;
/// `None` for anything else.
pub(crate) fn decode_bind_input(input: &[u8]) -> Option<Vec<SecretBinding>> {
    let mut cursor = std::io::Cursor::new(input);
    let Value::Array(items) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    // FIX 7990: any count decodes; large inputs travel as multipart parts.
    if cursor.position() != input.len() as u64 {
        return None;
    }
    let mut bindings: Vec<SecretBinding> = Vec::with_capacity(items.len());
    for item in &items {
        let binding = binding_from_value(item).ok()?;
        if binding.effector.is_empty()
            || binding.effector.len() > EFFECTOR_MAX_BYTES
            || bindings
                .iter()
                .any(|held| held.effector == binding.effector)
        {
            return None;
        }
        bindings.push(binding);
    }
    Some(bindings)
}
