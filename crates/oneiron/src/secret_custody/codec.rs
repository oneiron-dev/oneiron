//! MessagePack body codec for custody records, bands, floors, and bindings.

use std::collections::BTreeMap;

use rmpv::Value;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::floor::{as_u64, required_value};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_STORED_SCHEMA_VERSION,
    SecretBinding, SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus, TierBand,
};
use crate::error::SecretError;

pub(super) fn invalid_body(reason: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(reason))
}

/// SECRET_CUSTODY is sealed from the raw and sync planes: no replicated or
/// rematerialization door carries it, whatever its class or portable dial
/// (C1, secscan 2026-10-14). A peer-supplied custody body is unauthenticated
/// against the owner, so a replica that stored one would let any same-vault
/// device rewrite a value, widen a binding, roll a generation back or bring a
/// revoked record back to life. The record writes ONLY through the local
/// doors ([`Vault::register_secret`], rotation and revocation). This is the ONE
/// rejection constructor every REJECTING door names, so a grep for it audits
/// the whole seal:
///
/// * the replicated write wall (`batch::apply_ops`' Put arm) — the CRDT replay
///   door never materializes a peer-supplied custody body. Public raw puts are
///   already refused one level up by the `Maintenance` classification
///   (`MaintenanceKindNotWritable`);
/// * the generic read doors [`Vault::get`] and [`Vault::get_raw`], whose bytes
///   would otherwise carry `value_bytes` in the clear — the ONLY sanctioned
///   value read is [`Vault::get_secret_value_in_txn`];
/// * the export scrub's malformed-key arm ([`crate::sync::window`]), which
///   quarantines a custody carrier filed under a non-canonical peer key;
/// * replayed tombstones (`replayed_tombstone_protection_in_txn`): a peer's
///   delete proves no owner intent, so a credential leaves only through the
///   local revoke door.
///
/// The SILENT doors are deliberately not errors: the sync selector
/// ([`crate::sync::selector`]) drops the byte from the export set, and reverse
/// rematerialization and window egress skip-and-scrub it. None has a caller
/// to fail.
pub(crate) fn reject_secret_custody_byte() -> Error {
    invalid_body(CUSTODY_SEAL_REASON)
}

/// The seal's reason, for a caller that tells the seal apart from a decode
/// failure of the same error variant.
pub(crate) const CUSTODY_SEAL_REASON: &str =
    "secret custody is not eligible for this raw or sync door";

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

/// What a custody body holds in its value slot (KS-6): the plaintext value
/// under `value_bytes` (the owner archive's, a protected input's and a
/// transition's body DTO, stamped with the record's own schema version as
/// before; never a row at rest, nor an image's, KS-6 part 2), or the value sealed
/// under its credential custody key under `sealed_value` (the stored form,
/// stamped [`SECRET_CUSTODY_STORED_SCHEMA_VERSION`], CALLS `KS-6 credential
/// schema 2`).
pub(super) enum BodyValue {
    Plain(Vec<u8>),
    Sealed(Vec<u8>),
}

/// The stored body's value key: the value sealed under its custody key.
pub(super) const SECRET_CUSTODY_SEALED_VALUE_KEY: &str = "sealed_value";

/// Encodes a custody record into its MessagePack key-map body, the value in
/// the clear: the plaintext DTO, never the stored form.
pub fn encode_secret_custody_body(rec: &SecretCustodyRecord) -> Result<Vec<u8>> {
    encode_custody_map(rec, BodyValue::Plain(rec.value_bytes.clone()))
}

/// Encodes `rec`'s fields with `value` in its value slot, stamped as that
/// form is: the DTO with the record's version, the stored form with the
/// stored one.
pub(super) fn encode_custody_map(rec: &SecretCustodyRecord, value: BodyValue) -> Result<Vec<u8>> {
    let (schema_version, value_key, value) = match value {
        BodyValue::Plain(bytes) => (
            rec.schema_version,
            SECRET_CUSTODY_BODY_KEYS[4],
            Value::Binary(bytes),
        ),
        BodyValue::Sealed(bytes) => (
            SECRET_CUSTODY_STORED_SCHEMA_VERSION,
            SECRET_CUSTODY_SEALED_VALUE_KEY,
            Value::Binary(bytes),
        ),
    };
    let map = Value::Map(vec![
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[0]),
            Value::from(u64::from(schema_version)),
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
        (Value::from(value_key), value),
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
/// on write. A missing required key is a body-schema reject. The plaintext
/// DTO only: a stored body, whose value is sealed, is refused here and
/// opens through the custody doors (KS-6).
pub fn decode_secret_custody_body(bytes: &[u8]) -> Result<SecretCustodyRecord> {
    let (mut record, value) = decode_custody_map(bytes)?;
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
pub(super) fn decode_custody_map(bytes: &[u8]) -> Result<(SecretCustodyRecord, BodyValue)> {
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

    let record = SecretCustodyRecord {
        schema_version,
        name,
        class,
        device_only,
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

/// The label a register's framed protected input opens with: the record's
/// body, then the text of the manifest its recorder resolved it from (CALLS
/// CUSTODY_MANIFEST_RECHECK). A bare record body names no manifest text.
const REGISTER_INPUT_FRAME: &[u8] = b"oneiron/custody-register-input/v1\0";

/// The longest effector a binding names, at the bind door and in a bind's
/// protected input.
pub(super) const EFFECTOR_MAX_BYTES: usize = 256;

/// A register's protected input: `record`'s body, value in it, framed with
/// the text of the manifest its door resolved it from when there is one;
/// the bare body when there is none.
pub(super) fn encode_register_input(
    record: &SecretCustodyRecord,
    manifest: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = Zeroizing::new(encode_secret_custody_body(record)?);
    let Some(manifest) = manifest else {
        return Ok(body);
    };
    let len = u32::try_from(body.len())
        .map_err(|_| invalid_body("secret custody body is too large to frame"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        REGISTER_INPUT_FRAME.len() + 4 + body.len() + manifest.len(),
    ));
    out.extend_from_slice(REGISTER_INPUT_FRAME);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(manifest.as_bytes());
    Ok(out)
}

/// The record a register's protected input holds, value in it, and the
/// manifest text it is framed with, if any; `None` for anything else.
pub(super) fn decode_register_input(input: &[u8]) -> Option<(SecretCustodyRecord, Option<String>)> {
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

/// A bind's protected input: every binding the record takes, in the body's
/// binding shape (CALLS CUSTODY_BIND_TRAVEL).
pub(super) fn encode_bind_input(bindings: &[SecretBinding]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Array(bindings.iter().map(binding_to_value).collect()),
    )
    .map_err(|_| invalid_body("encode secret bindings"))?;
    Ok(out)
}

/// The bindings a bind's protected input holds: one array of any count,
/// each naming its own effector of 1 to 256 bytes, with nothing after it;
/// `None` for anything else.
pub(super) fn decode_bind_input(input: &[u8]) -> Option<Vec<SecretBinding>> {
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
