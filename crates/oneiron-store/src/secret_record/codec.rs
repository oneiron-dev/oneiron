//! MessagePack body codec for custody records, bands, floors, and bindings.

use std::collections::BTreeMap;

use rmpv::Value;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::secret_record::types::CustodyClass;
use crate::secret_record::types::CustodyTier;
use crate::secret_record::types::SECRET_CUSTODY_SCHEMA_VERSION;
use crate::secret_record::types::SecretBinding;
use crate::secret_record::types::SecretCustodyFloor;
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

/// A custody floor in the body's MessagePack shape. Value-free: the record's
/// encoder in the engine (`oneiron::secret_record::codec`) writes its floor
/// snapshot with it.
pub fn floor_to_value(floor: &SecretCustodyFloor) -> Value {
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

/// One binding in the body's MessagePack shape, shared by the record's
/// encoder in the engine and the bind input below. Value-free.
pub fn binding_to_value(binding: &SecretBinding) -> Value {
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

/// The stored body's value key: the value sealed under its custody key.
pub const SECRET_CUSTODY_SEALED_VALUE_KEY: &str = "sealed_value";

/// The label a register's framed protected input opens with: the record's
/// body, then the text of the manifest its recorder resolved it from (CALLS
/// CUSTODY_MANIFEST_RECHECK). A bare record body names no manifest text.
pub const REGISTER_INPUT_FRAME: &[u8] = b"oneiron/custody-register-input/v1\0";

/// The longest effector a binding names, at the bind door and in a bind's
/// protected input.
pub const EFFECTOR_MAX_BYTES: usize = 256;

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
