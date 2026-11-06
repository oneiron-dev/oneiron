//! Core half of `secret_lease::codec`: its store-layer items live in `oneiron_store::secret_lease::codec` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::secret_lease::codec::*;

use super::types::{
    FileIdentity, LocalRegistration, SECRET_MATERIALIZATION_RECEIPT_KIND, SecretLease,
    SecretLeaseStatus, SecretMaterializationReceipt, StoredLocalRegistration,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::secret_record::CustodyTier;
use crate::side_table::{self, HexId, Raw, RawValue, SideTable};
use rmpv::Value;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Side tables
// ---------------------------------------------------------------------------

/// T1/T2 secret-materialization lease row. Key: hex32(lease id).
pub(super) const SECRET_LEASE: SideTable<HexId, SecretLease, Raw> =
    SideTable::new(&side_table::SECRET_LEASE);

/// Durable receipt written before a secret value is returned from materialization. Key:
/// hex32(receipt id).
pub(super) const SECRET_MATERIALIZATION_RECEIPT: SideTable<
    HexId,
    SecretMaterializationReceipt,
    Raw,
> = SideTable::new(&side_table::SECRET_MATERIALIZATION_RECEIPT);

/// T2 local-file registration for a materialized secret. Key: hex32(lease id).
pub(super) const SECRET_LOCAL_REGISTRATION: SideTable<HexId, StoredLocalRegistration, Raw> =
    SideTable::new(&side_table::SECRET_LOCAL_REGISTRATION);

impl RawValue for SecretLease {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(encode_secret_lease_body(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        Ok(decode_secret_lease_body(bytes)?)
    }
}

impl RawValue for SecretMaterializationReceipt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(encode_materialization_receipt_body(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        Ok(decode_materialization_receipt_body(bytes)?)
    }
}

impl RawValue for StoredLocalRegistration {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(encode_local_registration_body(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        Ok(decode_local_registration_body(bytes)?)
    }
}

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

/// Decodes a materialization-receipt body. The RECEIPT side table's
/// `RawValue::from_raw` is the only non-test reader today: the row's
/// consumer surface (CSTDY-02/SECRET-04) lands on later stack layers.
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
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[6],
            Value::from(stored.file_identity.dev),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[7],
            Value::from(stored.file_identity.ino),
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
        file_identity: FileIdentity {
            dev: u64_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[6],
                "registration file_dev",
            )?,
            ino: u64_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[7],
                "registration file_ino",
            )?,
        },
        removal_error,
        removal_attempted_at,
    })
}
