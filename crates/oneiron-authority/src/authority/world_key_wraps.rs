//! A private world's key records and their wire codec (world privacy P6b).
//!
//! A world key is wrapped to each machine that may read the world and to the
//! owner's recovery root. Each record names one key, the commitment that
//! pins its bytes, the settings revision it was wrapped under, and one
//! sealed envelope per recipient. The records carry public facts and opaque
//! envelopes only; a key or a seed never rides the log.
//!
//! Every write door runs the same key-free checks: the list bounds, no
//! recipient twice, and each envelope's header matching the record before
//! any key derivation could run. Who may sign a record, and which records
//! count, is the fold's judgement.

use oneiron_crypto::{Envelope, Purpose, SuiteId, TAG_LEN, WrapParams, WrapType};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_WORLD_KEY_WRAPS: &str = "world_key_wraps";
/// The crypto epoch every world-key envelope is sealed at.
pub const WORLD_KEY_EPOCH: u64 = 1;
/// The key generation P6b mints. Rotation (P11) is not ratified; the field is
/// bound now so that rotation does not change the format.
pub const FIRST_GENERATION: u64 = 1;
/// At most this many recipients in one record.
pub const WORLD_KEY_WRAPS_MAX: usize = 64;
/// The longest envelope one record carries, in bytes.
pub const WORLD_KEY_ENVELOPE_MAX_BYTES: usize = 4 * 1024;
/// The sealed payload: label, owner, policy revision, key.
pub const WORLD_KEY_PAYLOAD_LABEL: &[u8] = b"oneiron/world-key/v1\0";
pub const WORLD_KEY_PAYLOAD_LEN: usize = WORLD_KEY_PAYLOAD_LABEL.len() + 16 + 32 + 32;
const POLICY_REVISION_CONTEXT: &[u8] = b"oneiron/world-policy-revision/v1";
const WORLD_KEY_WRAPS_KEYS: [&str; 9] = [
    OP_KEY_KIND,
    "world",
    "generation",
    "mint",
    "commitment",
    "owner",
    "policy",
    "machine",
    "wraps",
];

/// One world key: the world, its generation, and the random id of the mint
/// that made it. The current key is the greatest `(generation, mint)`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct WorldKeyId {
    pub world: EntityId,
    pub generation: u64,
    pub mint: [u8; 16],
}

impl WorldKeyId {
    /// The envelope `key_id`: world (16) ‖ generation (8, big-endian) ‖ mint (16).
    #[must_use]
    pub fn envelope_key_id(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..16].copy_from_slice(self.world.as_bytes());
        out[16..24].copy_from_slice(&self.generation.to_be_bytes());
        out[24..].copy_from_slice(&self.mint);
        out
    }
}

/// The world's settings as the wrapping machine saw them: a digest of the
/// world's live settings edits. All zero means no edit.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PolicyRevision(pub [u8; 32]);

impl PolicyRevision {
    /// `BLAKE3("oneiron/world-policy-revision/v1" ‖ the sorted live edit
    /// hashes)`, or zero for a world nobody edited.
    #[must_use]
    pub fn of(live: impl IntoIterator<Item = AuthorityEntryHash>) -> Self {
        let mut live: Vec<_> = live.into_iter().collect();
        if live.is_empty() {
            return Self([0; 32]);
        }
        live.sort_unstable();
        live.dedup();
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_REVISION_CONTEXT);
        for hash in live {
            hasher.update(&hash);
        }
        Self(*hasher.finalize().as_bytes())
    }
}

/// Who one envelope opens for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum WrapRecipient {
    /// A machine (its MACHINE row) through its machine secret.
    Machine(EntityId),
    /// The recovery root, through the kit.
    RecoveryRoot(RecoveryRootId),
}

impl WrapRecipient {
    /// The envelope `recipient`: 0x01 ‖ machine id (17 B), or 0x02 ‖ root id (33 B).
    #[must_use]
    pub fn envelope_recipient(&self) -> Vec<u8> {
        let (tag, id): (u8, &[u8]) = match self {
            Self::Machine(machine) => (0x01, &machine.as_bytes()[..]),
            Self::RecoveryRoot(root) => (0x02, &root.0[..]),
        };
        let mut out = Vec::with_capacity(1 + id.len());
        out.push(tag);
        out.extend_from_slice(id);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [0x01, id @ ..] => {
                let id = <[u8; 16]>::try_from(id).map_err(|_| invalid_authority())?;
                Ok(Self::Machine(
                    EntityId::from_bytes(id).map_err(|_| invalid_authority())?,
                ))
            }
            [0x02, id @ ..] => Ok(Self::RecoveryRoot(RecoveryRootId(
                <[u8; 32]>::try_from(id).map_err(|_| invalid_authority())?,
            ))),
            _ => Err(invalid_authority()),
        }
    }
}

/// One machine's wraps of one world key, signed by that machine's install
/// key: a per-world side-branch entry, like the world's settings edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldKeyWrapsRecord {
    pub key: WorldKeyId,
    /// `BLAKE3-derive_key("oneiron/world-key-commitment/v1", key_id ‖ key)`.
    pub commitment: [u8; 32],
    /// The vault owner PERSON.
    pub owner: EntityId,
    /// The world's settings revision at the record's parents.
    pub policy: PolicyRevision,
    /// The signing machine.
    pub machine: EntityId,
    /// One sealed envelope per recipient.
    pub wraps: Vec<(WrapRecipient, Vec<u8>)>,
}

impl WorldKeyWrapsRecord {
    /// The record alone: the bounds, no recipient twice, never base reality.
    pub fn validate(&self) -> Result<()> {
        if self.key.world == oneiron_contracts::claim::base_world_id()
            || self.wraps.is_empty()
            || self.wraps.len() > WORLD_KEY_WRAPS_MAX
            || self
                .wraps
                .iter()
                .any(|(_, envelope)| envelope.len() > WORLD_KEY_ENVELOPE_MAX_BYTES)
        {
            return Err(invalid_authority());
        }
        let mut recipients: Vec<_> = self.wraps.iter().map(|(to, _)| to).collect();
        recipients.sort_unstable();
        recipients.dedup();
        if recipients.len() != self.wraps.len() {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The entry the record rides: one Ed25519 signer and no cosign, and
    /// every envelope's header made for exactly this record, its vault and
    /// its list entry. No key derivation runs here.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let Some(vault_id) = entry.vault_id else {
            return Err(invalid_authority());
        };
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
            return Err(invalid_authority());
        }
        let key_id = self.key.envelope_key_id();
        for (recipient, bytes) in &self.wraps {
            let envelope = Envelope::parse(bytes).map_err(|_| invalid_authority())?;
            let header = envelope.header();
            let kem_ok = matches!(
                header.wrap_params,
                WrapParams::Hybrid { kem_suite, .. } if kem_suite == SuiteId::KEM_X25519_MLKEM1024_V1
            );
            if header.purpose != Purpose::WorldDek
                || header.wrap != WrapType::HybridCapsule
                || header.suite != SuiteId::XCHACHA20POLY1305_V1
                || !kem_ok
                || header.epoch != WORLD_KEY_EPOCH
                || header.vault_id[..] != vault_id[..]
                || header.key_id[..] != key_id[..]
                || header.recipient != recipient.envelope_recipient()
                || header.ciphertext_len as usize != WORLD_KEY_PAYLOAD_LEN + TAG_LEN
            {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }
}

pub(super) fn world_key_wraps_value(record: &WorldKeyWrapsRecord) -> Value {
    let wraps = record
        .wraps
        .iter()
        .map(|(recipient, envelope)| {
            Value::Array(vec![
                Value::Binary(recipient.envelope_recipient()),
                Value::Binary(envelope.clone()),
            ])
        })
        .collect();
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_WORLD_KEY_WRAPS),
        ),
        (Value::from("world"), Value::from(record.key.world.to_hex())),
        (
            Value::from("generation"),
            Value::from(record.key.generation),
        ),
        (Value::from("mint"), binary_value_16(record.key.mint)),
        (Value::from("commitment"), binary_value(record.commitment)),
        (Value::from("owner"), Value::from(record.owner.to_hex())),
        (Value::from("policy"), binary_value(record.policy.0)),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (Value::from("wraps"), Value::Array(wraps)),
    ])
}

pub(super) fn decode_world_key_wraps(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &WORLD_KEY_WRAPS_KEYS)?;
    let mint = match required(entries, "mint")? {
        Value::Binary(bytes) => {
            <[u8; 16]>::try_from(&bytes[..]).map_err(|_| invalid_authority())?
        }
        _ => return Err(invalid_authority()),
    };
    let Value::Array(list) = required(entries, "wraps")? else {
        return Err(invalid_authority());
    };
    if list.len() > WORLD_KEY_WRAPS_MAX {
        return Err(invalid_authority());
    }
    let wraps = list
        .iter()
        .map(|pair| match pair {
            Value::Array(pair) => match &pair[..] {
                [Value::Binary(recipient), Value::Binary(envelope)] => {
                    Ok((WrapRecipient::decode(recipient)?, envelope.clone()))
                }
                _ => Err(invalid_authority()),
            },
            _ => Err(invalid_authority()),
        })
        .collect::<Result<_>>()?;
    Ok(AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
        key: WorldKeyId {
            world: super::machine_profile::decode_canonical_id(required(entries, "world")?)?,
            generation: required(entries, "generation")?
                .as_u64()
                .ok_or_else(invalid_authority)?,
            mint,
        },
        commitment: decode_hash(required(entries, "commitment")?)?,
        owner: super::machine_profile::decode_canonical_id(required(entries, "owner")?)?,
        policy: PolicyRevision(decode_hash(required(entries, "policy")?)?),
        machine: super::machine_profile::decode_canonical_id(required(entries, "machine")?)?,
        wraps,
    }))
}
