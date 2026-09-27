//! Resident ownership of skill forks: an immutable birth mark, not a claim on the shared base.

use rmpv::Value;

use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::store::Store;

use super::SkillRecord;

pub(crate) const RESIDENT_PROVENANCE_KEY: &str = "residentActor";

/// A fork's owner, if it has one. Invalid/duplicate marks refuse the read;
/// an ambiguous owner must never be interpreted as an unowned shared skill.
pub(crate) fn resident_of(record: &SkillRecord) -> Result<Option<EntityId>> {
    let Value::Map(entries) = &record.provenance else {
        return Ok(None);
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(RESIDENT_PROVENANCE_KEY) {
            continue;
        }
        if found.is_some() {
            return Err(invalid_owner());
        }
        let hex = value.as_str().ok_or_else(invalid_owner)?;
        found = Some(EntityId::from_hex(hex).map_err(|_| invalid_owner())?);
    }
    Ok(found)
}

fn invalid_owner() -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(
        "residentActor must name one valid actor entity id",
    ))
}

/// Resolve a resident in the same snapshot as a skill birth or a pack stamp.
/// A replicated Candidate may wait for an out-of-order actor row, but an
/// active row cannot use the unresolved reference; a wrong-kind row never can.
pub(crate) fn require_resident_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    resident: &EntityId,
    defer_missing_candidate: bool,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, resident.as_bytes())? else {
        return if defer_missing_candidate {
            Ok(false)
        } else {
            Err(invalid_owner())
        };
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("resident entity header"))?;
    if !matches!(
        header.entity_type,
        ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF
    ) {
        return Err(invalid_owner());
    }
    Ok(true)
}

/// Durable per-skill-id owner, including explicit ABSENCE. Deleting the
/// entity does not free its identity for a different resident on recreation.
const OWNER_MARKER_PREFIX: &[u8] = b"skill:resident_owner:v1:";

fn owner_marker_key(skill: &EntityId) -> Vec<u8> {
    let mut key = OWNER_MARKER_PREFIX.to_vec();
    key.extend_from_slice(skill.as_bytes());
    key
}

pub(crate) fn check_owner_marker_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<()> {
    let owner = resident_of(record)?;
    let key = owner_marker_key(skill);
    let mut encoded = vec![1_u8, u8::from(owner.is_some())];
    if let Some(owner) = owner {
        encoded.extend_from_slice(owner.as_bytes());
    }
    if let Some(prior) = store.vault_meta.get(txn, &key)? {
        if prior.as_ref() != encoded.as_slice() {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "skill id cannot change resident ownership across deletion or replay",
            )));
        }
    } else {
        store.vault_meta.put(txn, &key, &encoded)?;
    }
    Ok(())
}

/// The shared SKILL write chokepoint: bind the ID for life, then verify the
/// owner is real before the record can load. Only an out-of-order replicated
/// Candidate may wait for its actor row; active replay never may.
pub(crate) fn validate_owner_put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
    replicated: bool,
) -> Result<()> {
    check_owner_marker_in_txn(store, txn, skill, record)?;
    if let Some(resident) = resident_of(record)? {
        let deferred = replicated && record.lifecycle_status == super::SkillLifecycle::Candidate;
        if require_resident_in_txn(store, txn, &resident, deferred)? {
            register_resident_in_txn(store, txn, &resident)?;
        }
    }
    Ok(())
}

const REGISTERED_PREFIX: &[u8] = b"skill:resident_registered:v1:";

fn registration_key(resident: &EntityId) -> Vec<u8> {
    let mut key = REGISTERED_PREFIX.to_vec();
    key.extend_from_slice(resident.as_bytes());
    key
}

pub(crate) fn register_resident_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    resident: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &registration_key(resident), &[1])?;
    Ok(())
}

pub(crate) fn is_registered(vault: &crate::Vault, resident: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&txn, &registration_key(resident))?
        .as_deref()
        == Some(&[1][..]))
}

/// One attempt has one resident stamp. The scoped pack doors write this in the
/// same transaction as the manifest; attribution cannot infer a resident from
/// a caller-chosen actor id or a lease-owner string.
const RECEIPT_OWNER_PREFIX: &[u8] = b"skill:resident_receipt:v1:";

fn receipt_key(receipt: &str) -> Vec<u8> {
    let mut key = RECEIPT_OWNER_PREFIX.to_vec();
    key.extend_from_slice(receipt.as_bytes());
    key
}

pub(crate) fn bind_receipt_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    resident: &EntityId,
) -> Result<()> {
    require_resident_in_txn(&vault.store, txn, resident, false)?;
    register_resident_in_txn(&vault.store, txn, resident)?;
    let key = receipt_key(receipt);
    if let Some(held) = vault.store.vault_meta.get(txn, &key)? {
        if held.as_ref() != resident.as_bytes() {
            return Err(Error::InvalidClaimBody(
                "attempt belongs to a different resident",
            ));
        }
    } else {
        vault.store.vault_meta.put(txn, &key, resident.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn receipt_resident(vault: &crate::Vault, receipt: &str) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    receipt_resident_in_txn(&vault.store, &txn, receipt)
}

pub(crate) fn receipt_resident_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Option<EntityId>> {
    store
        .vault_meta
        .get(txn, &receipt_key(receipt))?
        .map(|bytes| {
            let raw: [u8; 16] = bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("resident receipt owner"))?;
            EntityId::from_bytes(raw)
        })
        .transpose()
}

const RECEIPT_SKILL_PREFIX: &[u8] = b"skill:resident_loaded_skill:v1:";

fn receipt_skill_key(receipt: &str, skill: &EntityId) -> Vec<u8> {
    let mut key = RECEIPT_SKILL_PREFIX.to_vec();
    key.extend_from_slice(&(receipt.len() as u64).to_be_bytes());
    key.extend_from_slice(receipt.as_bytes());
    key.extend_from_slice(skill.as_bytes());
    key
}

pub(crate) fn bind_skill_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    skill: &EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(txn, &receipt_skill_key(receipt, skill), &[1])?;
    Ok(())
}

pub(crate) fn receipt_loaded_skill(
    vault: &crate::Vault,
    receipt: &str,
    skill: &EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&txn, &receipt_skill_key(receipt, skill))?
        .as_deref()
        == Some(&[1][..]))
}
