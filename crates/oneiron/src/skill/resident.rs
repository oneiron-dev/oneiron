//! Resident ownership of skill forks: an immutable birth mark, not a claim on the shared base.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

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
            return Err(Error::InvalidConfig(
                "duplicate resident skill owner".into(),
            ));
        }
        let hex = value
            .as_str()
            .ok_or_else(|| Error::InvalidConfig("invalid resident skill owner".into()))?;
        found = Some(EntityId::from_hex(hex)?);
    }
    Ok(found)
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
    vault
        .store
        .vault_meta
        .get(&txn, &receipt_key(receipt))?
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
