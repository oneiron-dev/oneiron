//! The owner's recovery root record and its wire codec (world privacy P6b).
//!
//! A root is its id: the id binds the vault and both keys its seed expands to,
//! the hybrid recovery key that world keys are wrapped to and the Ed25519
//! anchor that signs the record. The anchor alone signs it, which proves the
//! signer holds the seed; the seed itself never leaves the kit.

use oneiron_crypto::HybridPublicKey;
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_OWNER_ROOT: &str = "owner_root";
const ROOT_ID_CONTEXT: &str = "oneiron/world-recovery-root-id/v2";
const OWNER_ROOT_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    "owner",
    "root",
    "recovery_suite",
    "recovery_key",
    "anchor_key",
];

/// A root's public id, and the fingerprint the owner carries between machines
/// when pairing. A root that copies the recovery key under another anchor has
/// another id.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RecoveryRootId(pub [u8; 32]);

impl RecoveryRootId {
    /// `BLAKE3-derive_key("oneiron/world-recovery-root-id/v2", vault_id ‖ recovery_key ‖ anchor_key)`.
    #[must_use]
    pub fn of(vault_id: &[u8; 32], recovery_key: &HybridPublicKey, anchor_key: &[u8; 32]) -> Self {
        Self::of_encoded(vault_id, &recovery_key.to_bytes(), anchor_key)
    }

    fn of_encoded(vault_id: &[u8; 32], recovery_key: &[u8], anchor_key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(ROOT_ID_CONTEXT);
        hasher.update(vault_id);
        hasher.update(recovery_key);
        hasher.update(anchor_key);
        Self(*hasher.finalize().as_bytes())
    }
}

/// One root, as its anchor signs it into the vault's main log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRootRecord {
    /// The vault owner PERSON.
    pub owner: EntityId,
    pub root: RecoveryRootId,
    /// The recovery keypair's public half (suite 0x0101).
    pub recovery_key: MachineEncryptionKey,
    /// The owner anchor's Ed25519 key.
    pub anchor_key: [u8; 32],
}

impl OwnerRootRecord {
    /// The record alone: the recovery key passes the FIPS 203 import check and
    /// the anchor is an Ed25519 key.
    pub fn validate(&self) -> Result<()> {
        self.recovery_public_key()?;
        ed25519_dalek::VerifyingKey::from_bytes(&self.anchor_key)
            .map_err(|_| invalid_authority())?;
        Ok(())
    }

    /// The recovery key, imported.
    pub fn recovery_public_key(&self) -> Result<HybridPublicKey> {
        self.recovery_key.validate()?;
        HybridPublicKey::from_bytes(&self.recovery_key.key).map_err(|_| invalid_authority())
    }

    /// The entry the record rides: its id is the entry vault's and both keys',
    /// and the anchor signs it alone, with no cosign.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let Some(vault_id) = entry.vault_id else {
            return Err(invalid_authority());
        };
        if self.root
            != RecoveryRootId::of_encoded(&vault_id, &self.recovery_key.key, &self.anchor_key)
            || entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || entry.signer.public_key != AuthorityKey::Ed25519(self.anchor_key)
            || !entry.cosigns.is_empty()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn owner_root_value(record: &OwnerRootRecord) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_OWNER_ROOT)),
        (Value::from("owner"), Value::from(record.owner.to_hex())),
        (Value::from("root"), binary_value(record.root.0)),
        (
            Value::from("recovery_suite"),
            Value::from(record.recovery_key.suite),
        ),
        (
            Value::from("recovery_key"),
            Value::Binary(record.recovery_key.key.clone()),
        ),
        (Value::from("anchor_key"), binary_value(record.anchor_key)),
    ])
}

pub(super) fn decode_owner_root(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &OWNER_ROOT_KEYS)?;
    let key = match required(entries, "recovery_key")? {
        Value::Binary(bytes) if bytes.len() == MACHINE_ENCRYPTION_KEY_LEN => bytes.clone(),
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::OwnerRoot(OwnerRootRecord {
        owner: super::machine_profile::decode_canonical_id(required(entries, "owner")?)?,
        root: RecoveryRootId(decode_hash(required(entries, "root")?)?),
        recovery_key: MachineEncryptionKey {
            suite: required(entries, "recovery_suite")?
                .as_u64()
                .and_then(|suite| u16::try_from(suite).ok())
                .ok_or_else(invalid_authority)?,
            key,
        },
        anchor_key: decode_hash(required(entries, "anchor_key")?)?,
    }))
}
