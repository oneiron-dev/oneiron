//! A vault data-key generation and its delivery to the owner's other devices.
//!
//! The owner's act moves this device to a new data key. This record carries
//! the new key to every other trusted owner machine: one sealed capsule per
//! machine, the commitment naming the new key, and the link that puts the old
//! key under it. A device that folds a counted entry with a capsule for
//! itself adopts the new generation with no owner unlock.
//!
//! Every write door runs the same key-free checks: the list bounds, the
//! capsules in ascending machine order with no machine twice, and each
//! capsule's header matching the record before any key derivation could run.
//! Who may sign a record, and which records count, is the fold's judgement.

use oneiron_crypto::{Envelope, Purpose, SuiteId, TAG_LEN, WrapParams, WrapType};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_DATA_KEY_GENERATION: &str = "data_key_generation";
/// The crypto epoch every data-key capsule is sealed at.
pub const DATA_KEY_GENERATION_EPOCH: u64 = 1;
/// At most this many capsules in one record.
pub const DATA_KEY_GENERATION_CAPSULES_MAX: usize = 64;
/// The longest capsule one record carries, in bytes.
pub const DATA_KEY_GENERATION_ENVELOPE_MAX_BYTES: usize = 4 * 1024;
/// The longest link bytes one record carries.
pub const DATA_KEY_GENERATION_LINK_MAX_BYTES: usize = 4 * 1024;
/// The sealed payload: label, commitment, key.
pub const DATA_KEY_GENERATION_PAYLOAD_LABEL: &[u8] = b"oneiron/data-key-generation/v1\0";
pub const DATA_KEY_GENERATION_PAYLOAD_LEN: usize =
    DATA_KEY_GENERATION_PAYLOAD_LABEL.len() + 32 + 32;
const DATA_KEY_GENERATION_KEYS: [&str; 9] = [
    OP_KEY_KIND,
    "vault",
    "generation",
    "commitment",
    "previous",
    "link",
    "machine",
    "capsules",
    "cause",
];

/// Why the owner started the generation this record delivers. It matches
/// `oneiron::world_keys::DataKeyGenerationCause`; the wire code is the
/// discriminant, and an unknown code refuses at decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DataKeyGenerationCause {
    /// The owner asked for a new generation.
    OwnerRequest = 0,
    /// The kit-only switch moves to a new key.
    KitOnlySwitch = 1,
}

impl DataKeyGenerationCause {
    /// The wire code.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The cause for `code`. An unknown code is refused.
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::OwnerRequest),
            1 => Ok(Self::KitOnlySwitch),
            _ => Err(invalid_authority()),
        }
    }
}

/// One data-key generation's delivery, signed by the acting machine's install
/// key: a main-log entry, so every machine the owner admits folds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataKeyGenerationRecord {
    /// The vault, as the containing entry names it.
    pub vault: AuthorityVaultId,
    /// The new generation number, at least 1.
    pub generation: u32,
    /// The commitment naming the new key.
    pub commitment: [u8; 32],
    /// The commitment naming the key it replaces.
    pub previous: [u8; 32],
    /// The exact envelope bytes of the LINKS row the act wrote for
    /// `generation`: the old key sealed under the new one.
    pub link: Vec<u8>,
    /// The signing machine.
    pub machine: EntityId,
    /// One sealed capsule per recipient machine, ascending by machine.
    pub capsules: Vec<(EntityId, Vec<u8>)>,
    /// Why the owner started this generation.
    pub cause: DataKeyGenerationCause,
}

impl DataKeyGenerationRecord {
    /// The envelope `key_id`: vault (32) ‖ generation (4, big-endian) ‖
    /// commitment (32).
    #[must_use]
    pub fn envelope_key_id(&self) -> [u8; 68] {
        let mut out = [0u8; 68];
        out[..32].copy_from_slice(&self.vault);
        out[32..36].copy_from_slice(&self.generation.to_be_bytes());
        out[36..].copy_from_slice(&self.commitment);
        out
    }

    /// The record alone: the bounds, the capsules ascending with no machine
    /// twice, and a generation past zero. A lone device logs its act with no
    /// capsules; the entry still names the generation for the fold.
    pub fn validate(&self) -> Result<()> {
        if self.generation == 0
            || self.link.is_empty()
            || self.link.len() > DATA_KEY_GENERATION_LINK_MAX_BYTES
            || self.capsules.len() > DATA_KEY_GENERATION_CAPSULES_MAX
            || self
                .capsules
                .iter()
                .any(|(_, envelope)| envelope.len() > DATA_KEY_GENERATION_ENVELOPE_MAX_BYTES)
        {
            return Err(invalid_authority());
        }
        let mut ordered = self.capsules.iter().map(|(machine, _)| machine);
        let mut previous = ordered.next();
        for machine in ordered {
            if previous.is_some_and(|before| before >= machine) {
                return Err(invalid_authority());
            }
            previous = Some(machine);
        }
        Ok(())
    }

    /// The entry the record rides: one Ed25519 signer and no cosign, the
    /// entry's vault, and every capsule's header made for exactly this
    /// record, its vault and its list entry. No key derivation runs here.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let Some(vault_id) = entry.vault_id else {
            return Err(invalid_authority());
        };
        if self.vault != vault_id {
            return Err(invalid_authority());
        }
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
            return Err(invalid_authority());
        }
        let key_id = self.envelope_key_id();
        for (machine, bytes) in &self.capsules {
            let envelope = Envelope::parse(bytes).map_err(|_| invalid_authority())?;
            let header = envelope.header();
            let kem_ok = matches!(
                header.wrap_params,
                WrapParams::Hybrid { kem_suite, .. } if kem_suite == SuiteId::KEM_X25519_MLKEM1024_V1
            );
            if header.purpose != Purpose::DataKeyGeneration
                || header.wrap != WrapType::HybridCapsule
                || header.suite != SuiteId::XCHACHA20POLY1305_V1
                || !kem_ok
                || header.epoch != DATA_KEY_GENERATION_EPOCH
                || header.vault_id[..] != vault_id[..]
                || header.key_id[..] != key_id[..]
                || header.recipient != capsule_recipient(machine)
                || header.ciphertext_len as usize != DATA_KEY_GENERATION_PAYLOAD_LEN + TAG_LEN
            {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }
}

/// One capsule's envelope `recipient`: 0x01 ‖ machine id (17 B).
#[must_use]
pub fn capsule_recipient(machine: &EntityId) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(0x01);
    out.extend_from_slice(machine.as_bytes());
    out
}

fn decode_capsule_recipient(bytes: &[u8]) -> Result<EntityId> {
    match bytes {
        [0x01, id @ ..] => {
            let id = <[u8; 16]>::try_from(id).map_err(|_| invalid_authority())?;
            EntityId::from_bytes(id).map_err(|_| invalid_authority())
        }
        _ => Err(invalid_authority()),
    }
}

/// Canonical field order: kind, vault, generation, commitment, previous,
/// link, machine, capsules, cause.
pub(super) fn data_key_generation_value(record: &DataKeyGenerationRecord) -> Value {
    let capsules = record
        .capsules
        .iter()
        .map(|(machine, envelope)| {
            Value::Array(vec![
                Value::Binary(capsule_recipient(machine)),
                Value::Binary(envelope.clone()),
            ])
        })
        .collect();
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_DATA_KEY_GENERATION),
        ),
        (Value::from("vault"), binary_value(record.vault)),
        (
            Value::from("generation"),
            Value::from(u64::from(record.generation)),
        ),
        (
            Value::from("commitment"),
            binary_value(record.commitment),
        ),
        (Value::from("previous"), binary_value(record.previous)),
        (Value::from("link"), Value::Binary(record.link.clone())),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (Value::from("capsules"), Value::Array(capsules)),
        (
            Value::from("cause"),
            Value::from(u64::from(record.cause.code())),
        ),
    ])
}

pub(super) fn decode_data_key_generation(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &DATA_KEY_GENERATION_KEYS)?;
    let generation = required(entries, "generation")?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let generation = u32::try_from(generation).map_err(|_| invalid_authority())?;
    let link = match required(entries, "link")? {
        Value::Binary(link) => link.clone(),
        _ => return Err(invalid_authority()),
    };
    let Value::Array(list) = required(entries, "capsules")? else {
        return Err(invalid_authority());
    };
    if list.len() > DATA_KEY_GENERATION_CAPSULES_MAX {
        return Err(invalid_authority());
    }
    let capsules = list
        .iter()
        .map(|pair| match pair {
            Value::Array(pair) => match &pair[..] {
                [Value::Binary(recipient), Value::Binary(envelope)] => {
                    Ok((decode_capsule_recipient(recipient)?, envelope.clone()))
                }
                _ => Err(invalid_authority()),
            },
            _ => Err(invalid_authority()),
        })
        .collect::<Result<_>>()?;
    let cause = required(entries, "cause")?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let cause = u8::try_from(cause).map_err(|_| invalid_authority())?;
    Ok(AuthorityOp::DataKeyGeneration(DataKeyGenerationRecord {
        vault: decode_hash(required(entries, "vault")?)?,
        generation,
        commitment: decode_hash(required(entries, "commitment")?)?,
        previous: decode_hash(required(entries, "previous")?)?,
        link,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        capsules,
        cause: DataKeyGenerationCause::from_code(cause)?,
    }))
}
