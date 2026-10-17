//! The physical machine profile: the owner's signed answer when a machine
//! joins the vault, and its wire codec.
//!
//! A MACHINE row is public-writable address data. This op is the one place a
//! machine's standing lives, so a mesh address bind or a generic Put that
//! rewrites the row leaves it untouched. The entry's signer is the owner's
//! roster key; `machine_proof` is the machine's own signature over its
//! identity material, so the owner can re-issue the profile at a new revision
//! (change its role, remove it) without the machine taking part.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_MACHINE_PROFILE: &str = "machine_profile";
const MACHINE_PROFILE_PROOF_DOMAIN: &[u8] = b"oneiron/machine-profile/v1\0";
/// `kem-x25519-mlkem1024-v1` (OF-570): the one suite a machine's encryption
/// key may name.
pub const MACHINE_ENCRYPTION_SUITE_HYBRID_V1: u16 = 0x0101;
/// `ek_mlkem1024 || x25519_public`.
pub const MACHINE_ENCRYPTION_KEY_LEN: usize = 1568 + 32;
/// At most this many world edits one profile revision lists as seen.
pub const MACHINE_SEEN_WORLD_EDITS_MAX: usize = 4096;
const SEEN_WORLD_EDITS_KEY: &str = "seen_world_edits";
const MACHINE_PROFILE_KEYS: [&str; 9] = [
    OP_KEY_KIND,
    "machine",
    "owner",
    "machine_key",
    "encryption_suite",
    "encryption_key",
    "role",
    "revision",
    "machine_proof",
];

/// The owner's answer when a machine is added. Only `Yours` makes it mine.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MachineOwnership {
    Yours,
    WorkSchool,
    Rented,
}

/// What a machine is to the vault's owner.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MachineRole {
    /// A machine the owner added at the pairing ceremony.
    Owned(MachineOwnership),
    /// A hosted home node.
    HostedNode,
    /// A rented execution node (ARCH-0023b).
    ExecutionNode,
    /// Terminal: no later revision brings the machine back.
    Removed,
}

impl MachineRole {
    fn wire(self) -> &'static str {
        match self {
            Self::Owned(MachineOwnership::Yours) => "yours",
            Self::Owned(MachineOwnership::WorkSchool) => "work_school",
            Self::Owned(MachineOwnership::Rented) => "rented",
            Self::HostedNode => "hosted_node",
            Self::ExecutionNode => "execution_node",
            Self::Removed => "removed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "yours" => Self::Owned(MachineOwnership::Yours),
            "work_school" => Self::Owned(MachineOwnership::WorkSchool),
            "rented" => Self::Owned(MachineOwnership::Rented),
            "hosted_node" => Self::HostedNode,
            "execution_node" => Self::ExecutionNode,
            "removed" => Self::Removed,
            _ => return None,
        })
    }
}

/// A machine's public encryption key; P6 wraps world keys to it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct MachineEncryptionKey {
    pub suite: u16,
    pub key: Vec<u8>,
}

impl MachineEncryptionKey {
    /// Length and suite only. The FIPS 203 key check runs where the key is
    /// used to wrap (P6), in `oneiron-crypto`.
    pub fn validate(&self) -> Result<()> {
        if self.suite != MACHINE_ENCRYPTION_SUITE_HYBRID_V1
            || self.key.len() != MACHINE_ENCRYPTION_KEY_LEN
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// One revision of a machine's standing, signed by an owner roster key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct MachineProfile {
    /// The MACHINE row.
    pub machine: EntityId,
    /// The owner PERSON who answered at the ceremony.
    pub owner: EntityId,
    /// The machine install's Ed25519 key: it proves the machine on a
    /// connection and signs that machine's world-settings edits.
    pub machine_key: [u8; 32],
    pub encryption_key: MachineEncryptionKey,
    pub role: MachineRole,
    /// Strictly above the folded revision for this machine.
    pub revision: u64,
    /// `machine_key`'s signature over [`machine_profile_proof_transcript`].
    #[serde(with = "machine_proof_bytes")]
    pub machine_proof: [u8; 64],
    /// The world edits this machine signed that the revision's author had
    /// seen. When the revision takes the machine's "yours" away, those edits
    /// keep their effect; one it never saw raced it and counts only stricter.
    pub seen_world_edits: BTreeSet<AuthorityEntryHash>,
}

impl MachineProfile {
    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 || self.seen_world_edits.len() > MACHINE_SEEN_WORLD_EDITS_MAX {
            return Err(invalid_authority());
        }
        VerifyingKey::from_bytes(&self.machine_key).map_err(|_| invalid_authority())?;
        self.encryption_key.validate()
    }

    /// Whether the machine itself signed this identity material for `vault_id`.
    pub fn proof_verifies(&self, vault_id: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.machine_key) else {
            return false;
        };
        let transcript = machine_profile_proof_transcript(
            vault_id,
            self.machine,
            &self.machine_key,
            &self.encryption_key,
        );
        key.verify_strict(&transcript, &Signature::from_bytes(&self.machine_proof))
            .is_ok()
    }

    /// Mine is the owner's explicit answer, never derived.
    pub fn says_mine(&self) -> bool {
        self.role == MachineRole::Owned(MachineOwnership::Yours)
    }
}

/// The bytes a machine signs to join a vault. They bind the vault, the
/// machine row and both of its keys; the role and revision are the owner's.
pub fn machine_profile_proof_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    machine_key: &[u8; 32],
    encryption_key: &MachineEncryptionKey,
) -> Vec<u8> {
    let mut bytes = MACHINE_PROFILE_PROOF_DOMAIN.to_vec();
    bytes.extend_from_slice(vault_id);
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(machine_key);
    bytes.extend_from_slice(&encryption_key.suite.to_be_bytes());
    bytes.extend_from_slice(&encryption_key.key);
    bytes
}

pub(super) fn machine_profile_value(profile: &MachineProfile) -> Value {
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_MACHINE_PROFILE),
        ),
        (
            Value::from("machine"),
            Value::from(profile.machine.to_hex()),
        ),
        (Value::from("owner"), Value::from(profile.owner.to_hex())),
        (
            Value::from("machine_key"),
            binary_value(profile.machine_key),
        ),
        (
            Value::from("encryption_suite"),
            Value::from(profile.encryption_key.suite),
        ),
        (
            Value::from("encryption_key"),
            Value::Binary(profile.encryption_key.key.clone()),
        ),
        (Value::from("role"), Value::from(profile.role.wire())),
        (Value::from("revision"), Value::from(profile.revision)),
        (
            Value::from("machine_proof"),
            Value::Binary(profile.machine_proof.to_vec()),
        ),
    ];
    // Absent when empty, so a profile that saw no world edit keeps its bytes.
    if !profile.seen_world_edits.is_empty() {
        entries.push((
            Value::from(SEEN_WORLD_EDITS_KEY),
            Value::Array(
                profile
                    .seen_world_edits
                    .iter()
                    .map(|hash| binary_value(*hash))
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

pub(super) fn decode_machine_profile(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let seen_world_edits = match entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(SEEN_WORLD_EDITS_KEY)).then_some(value))
    {
        None => {
            validate_keys(entries, &MACHINE_PROFILE_KEYS)?;
            BTreeSet::new()
        }
        Some(value) => {
            let mut keys = MACHINE_PROFILE_KEYS.to_vec();
            keys.push(SEEN_WORLD_EDITS_KEY);
            validate_keys(entries, &keys)?;
            let hashes = decode_hash_array(value)?;
            let seen: BTreeSet<_> = hashes.iter().copied().collect();
            // Canonical only: non-empty, sorted and distinct.
            if seen.is_empty() || !hashes.iter().eq(seen.iter()) {
                return Err(invalid_authority());
            }
            seen
        }
    };
    let machine_proof = match required(entries, "machine_proof")? {
        Value::Binary(bytes) => <[u8; 64]>::try_from(bytes.as_slice()),
        _ => return Err(invalid_authority()),
    }
    .map_err(|_| invalid_authority())?;
    let key = match required(entries, "encryption_key")? {
        Value::Binary(bytes) => bytes.clone(),
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::MachineProfile(MachineProfile {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        owner: decode_canonical_id(required(entries, "owner")?)?,
        machine_key: decode_hash(required(entries, "machine_key")?)?,
        encryption_key: MachineEncryptionKey {
            suite: required(entries, "encryption_suite")?
                .as_u64()
                .and_then(|suite| u16::try_from(suite).ok())
                .ok_or_else(invalid_authority)?,
            key,
        },
        role: required(entries, "role")?
            .as_str()
            .and_then(MachineRole::parse)
            .ok_or_else(invalid_authority)?,
        revision: required(entries, "revision")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        machine_proof,
        seen_world_edits,
    }))
}

/// A 32-hex entity id, refused unless it round-trips (the `actor_ref` rule).
pub(super) fn decode_canonical_id(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_authority)?;
    let id = EntityId::from_hex(hex).map_err(|_| invalid_authority())?;
    if id.to_hex() != hex {
        return Err(invalid_authority());
    }
    Ok(id)
}

/// `machine_proof` in a serde image (OF-469 checkpoint v2) as one byte string
/// of exactly 64 bytes: serde's own arrays stop at 32. The signed wire codec
/// above is unchanged.
mod machine_proof_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        proof: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(proof)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        deserializer.deserialize_bytes(Proof)
    }

    struct Proof;

    impl Visitor<'_> for Proof {
        type Value = [u8; 64];

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("64 machine proof bytes")
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            <[u8; 64]>::try_from(bytes).map_err(|_| E::invalid_length(bytes.len(), &self))
        }
    }
}
