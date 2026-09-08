//! MessagePack body codec for custody records, bands, floors, and bindings.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::error::{Error, Result};

use super::floor::{as_u64, required_value};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus, TierBand,
};

pub(super) fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidSecretCustodyBody(reason)
}

/// ONE-1865 arms the replication and export posture for SECRET_CUSTODY; until
/// then the type byte is sealed from the raw and CRDT planes. This is the ONE
/// rejection constructor every REJECTING door names, so a grep for it audits
/// the whole seal:
///
/// * the replicated write wall (`batch::apply_ops`' Put arm) — the CRDT replay
///   door never materializes a peer-supplied custody body; the record writes
///   ONLY through [`Vault::register_secret`]. Public raw puts are already
///   refused one level up by the `Maintenance` classification
///   (`MaintenanceKindNotWritable(77)`);
/// * the generic read doors [`Vault::get`] and [`Vault::get_raw`], whose bytes
///   would otherwise carry `value_bytes` in the clear — the ONLY sanctioned
///   value read is [`Vault::get_secret_value_in_txn`];
/// * the export scrub's malformed-key arm ([`crate::sync::window`]), which
///   quarantines a custody carrier filed under a non-canonical peer key.
///
/// The two SILENT doors are deliberately not errors: the sync selector
/// ([`crate::sync::selector`]) drops the byte from the export set, and reverse
/// rematerialization skips-and-scrubs it. Neither has a caller to fail.
pub(crate) fn reject_secret_custody_byte() -> Error {
    invalid_body("secret custody records are sealed from the raw/CRDT planes until ONE-1865")
}

fn tier_band_to_value(band: &TierBand) -> Value {
    Value::Map(vec![
        (Value::from("min"), Value::from(u64::from(band.min.as_u8()))),
        (Value::from("max"), Value::from(u64::from(band.max.as_u8()))),
    ])
}

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

fn floor_to_value(floor: &SecretCustodyFloor) -> Value {
    let env = Value::Map(
        floor
            .env_bindings
            .iter()
            .map(|(k, v)| (Value::from(k.as_str()), Value::from(v.as_str())))
            .collect(),
    );
    Value::Map(vec![
        (Value::from("portable"), tier_band_to_value(&floor.portable)),
        (
            Value::from("device_bound"),
            tier_band_to_value(&floor.device_bound),
        ),
        (
            Value::from("cross_vault"),
            tier_band_to_value(&floor.cross_vault),
        ),
        (
            Value::from("rotation_max_age_secs"),
            match floor.rotation_max_age_secs {
                Some(n) => Value::from(n),
                None => Value::Nil,
            },
        ),
        (Value::from("env_bindings"), env),
    ])
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

fn binding_to_value(binding: &SecretBinding) -> Value {
    Value::Map(vec![
        (
            Value::from("effector"),
            Value::from(binding.effector.as_str()),
        ),
        (
            Value::from("tier_ceiling"),
            Value::from(u64::from(binding.tier_ceiling.as_u8())),
        ),
        (
            Value::from("scopes"),
            Value::Array(
                binding
                    .scopes
                    .iter()
                    .map(|s| Value::from(s.as_str()))
                    .collect(),
            ),
        ),
    ])
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

/// Encodes a custody record into its MessagePack key-map body.
pub fn encode_secret_custody_body(rec: &SecretCustodyRecord) -> Result<Vec<u8>> {
    let map = Value::Map(vec![
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[0]),
            Value::from(u64::from(rec.schema_version)),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[1]),
            Value::from(rec.name.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[2]),
            Value::from(rec.class.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[3]),
            Value::from(rec.device_only),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[4]),
            Value::Binary(rec.value_bytes.clone()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[5]),
            Value::from(rec.status.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[6]),
            Value::from(rec.registered_at),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[7]),
            match rec.rotated_at {
                Some(n) => Value::from(n),
                None => Value::Nil,
            },
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[8]),
            Value::from(u64::from(rec.rotation_generation)),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[9]),
            Value::Array(rec.bindings.iter().map(binding_to_value).collect()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[10]),
            Value::from(rec.manifest_ref.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[11]),
            Value::Array(
                rec.declared_paths
                    .iter()
                    .map(|p| Value::from(p.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[12]),
            floor_to_value(&rec.policy_floor_snapshot),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| invalid_body("encode secret custody body"))?;
    Ok(out)
}

/// Decodes a custody record from its MessagePack key-map body. All 13 keys
/// are required except `rotated_at` (nil-or-int): `bindings`, `manifest_ref`,
/// and `declared_paths` may be EMPTY (an empty array or string is still a
/// present, well-formed key) but must not be MISSING — a record is complete
/// on write. A missing required key is a body-schema reject.
pub fn decode_secret_custody_body(bytes: &[u8]) -> Result<SecretCustodyRecord> {
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
    let value_bytes = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[4]) {
        Some(Value::Binary(b)) => b.clone(),
        Some(Value::String(s)) => s.as_str().unwrap_or_default().as_bytes().to_vec(),
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

    Ok(SecretCustodyRecord {
        schema_version,
        name,
        class,
        device_only,
        value_bytes,
        status,
        registered_at,
        rotated_at,
        rotation_generation,
        bindings,
        manifest_ref,
        declared_paths,
        policy_floor_snapshot,
    })
}
