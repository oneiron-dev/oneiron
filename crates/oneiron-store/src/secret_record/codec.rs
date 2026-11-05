//! MessagePack body codec for custody records, bands, floors, and bindings.

use std::collections::BTreeMap;

use rmpv::Value;
use zeroize::Zeroizing;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::secret_record::types::CustodyClass;
use crate::secret_record::types::CustodyTier;
use crate::secret_record::types::SECRET_CUSTODY_BODY_KEYS;
use crate::secret_record::types::SECRET_CUSTODY_SCHEMA_VERSION;
use crate::secret_record::types::SECRET_CUSTODY_STORED_SCHEMA_VERSION;
use crate::secret_record::types::SecretBinding;
use crate::secret_record::types::SecretCustodyFloor;
use crate::secret_record::types::SecretCustodyRecord;
use crate::secret_record::types::SecretCustodyStatus;
use crate::secret_record::types::TierBand;
use oneiron_base::error::SecretError;

pub fn invalid_body(reason: &'static str) -> Error {
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
pub fn reject_secret_custody_byte() -> Error {
    invalid_body(CUSTODY_SEAL_REASON)
}

/// The seal's reason, for a caller that tells the seal apart from a decode
/// failure of the same error variant.
pub const CUSTODY_SEAL_REASON: &str = "secret custody is not eligible for this raw or sync door";

fn tier_band_to_value(band: &TierBand) -> Value {
    Value::Map(vec![
        (Value::from("min"), Value::from(u64::from(band.min.as_u8()))),
        (Value::from("max"), Value::from(u64::from(band.max.as_u8()))),
    ])
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

/// What a custody body holds in its value slot (KS-6): the plaintext value
/// under `value_bytes` (the owner archive's, a protected input's and a
/// transition's body DTO, stamped with the record's own schema version as
/// before; never a row at rest, nor an image's, KS-6 part 2), or the value sealed
/// under its credential custody key under `sealed_value` (the stored form,
/// stamped [`SECRET_CUSTODY_STORED_SCHEMA_VERSION`]).
pub enum BodyValue {
    Plain(Vec<u8>),
    Sealed(Vec<u8>),
}

/// The stored body's value key: the value sealed under its custody key.
pub const SECRET_CUSTODY_SEALED_VALUE_KEY: &str = "sealed_value";

/// Encodes a custody record into its MessagePack key-map body, the value in
/// the clear: the plaintext DTO, never the stored form.
pub fn encode_secret_custody_body(rec: &SecretCustodyRecord) -> Result<Vec<u8>> {
    encode_custody_map(rec, BodyValue::Plain(rec.value_bytes.clone()))
}

/// Encodes `rec`'s fields with `value` in its value slot, stamped as that
/// form is: the DTO with the record's version, the stored form with the
/// stored one.
pub fn encode_custody_map(rec: &SecretCustodyRecord, value: BodyValue) -> Result<Vec<u8>> {
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
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[13]),
            Value::from(rec.model_reveal_allowed),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| invalid_body("encode secret custody body"))?;
    Ok(out)
}

/// The label a register's framed protected input opens with: the record's
/// body, then the text of the manifest its recorder resolved it from (CALLS
/// CUSTODY_MANIFEST_RECHECK). A bare record body names no manifest text.
pub const REGISTER_INPUT_FRAME: &[u8] = b"oneiron/custody-register-input/v1\0";

/// The longest effector a binding names, at the bind door and in a bind's
/// protected input.
pub const EFFECTOR_MAX_BYTES: usize = 256;

/// A register's protected input: `record`'s body, value in it, framed with
/// the text of the manifest its door resolved it from when there is one;
/// the bare body when there is none.
pub fn encode_register_input(
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

/// A bind's protected input: every binding the record takes, in the body's
/// binding shape (CALLS CUSTODY_BIND_TRAVEL).
pub fn encode_bind_input(bindings: &[SecretBinding]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Array(bindings.iter().map(binding_to_value).collect()),
    )
    .map_err(|_| invalid_body("encode secret bindings"))?;
    Ok(out)
}
