//! Resident ownership of skill forks: an immutable birth mark, not a claim on the shared base.

use rmpv::Value;

use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
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

/// An attempt executor can also be a MACHINE system actor. This is NOT the
/// resident-fork owner check above: MACHINE must never gain fork ownership.
fn require_executor_in_txn(store: &Store, txn: &heed::RoTxn<'_>, actor: &EntityId) -> Result<()> {
    let raw = store
        .entities
        .get(txn, actor.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("attempt executor entity header"))?;
    if !matches!(
        header.entity_type,
        ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF | ENTITY_TYPE_MACHINE
    ) {
        return Err(Error::InvalidClaimBody(
            "attempt executor must be an actor entity",
        ));
    }
    Ok(())
}

/// Durable per-skill-id owner, including explicit ABSENCE. Deleting the
/// entity does not free its identity for a different resident on recreation.
const OWNER_MARKER: SideTable<EntityId, OwnerMarker, Raw> =
    SideTable::new(&side_table::SKILL_RESIDENT_OWNER);

/// [`OWNER_MARKER`]'s row: a version byte (1), a has-owner byte, then the owner id when there
/// is one.
#[derive(PartialEq, Eq)]
struct OwnerMarker(Option<EntityId>);

impl RawValue for OwnerMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut encoded = vec![1_u8, u8::from(self.0.is_some())];
        if let Some(owner) = self.0 {
            encoded.extend_from_slice(owner.as_bytes());
        }
        Ok(encoded)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let owner = match bytes {
            [1, 0] => None,
            [1, 1, owner @ ..] => Some(EntityId::decode_key(owner).ok_or_else(invalid_owner)?),
            _ => return Err(invalid_owner().into()),
        };
        Ok(Self(owner))
    }
}

pub(crate) fn check_owner_marker_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<()> {
    let marker = OwnerMarker(resident_of(record)?);
    if let Some(prior) = OWNER_MARKER.get(store, txn, skill)? {
        if prior != marker {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "skill id cannot change resident ownership across deletion or replay",
            )));
        }
    } else {
        OWNER_MARKER.put(store, txn, skill, &marker)?;
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
        // Sync carries the CURRENT blob, not necessarily a Candidate first.
        // An unresolved Candidate is inert; every other lawful lifecycle
        // state needs its owner before materialization and keeps a retry.
        if replicated
            && record.lifecycle_status != super::SkillLifecycle::Candidate
            && store.entities.get(txn, resident.as_bytes())?.is_none()
        {
            return Err(Error::Artifact(
                ArtifactError::ResidentOwnerDependencyPending,
            ));
        }
        let deferred = replicated && record.lifecycle_status == super::SkillLifecycle::Candidate;
        require_resident_in_txn(store, txn, &resident, deferred)?;
    }
    Ok(())
}

/// One attempt has one resident stamp. The scoped pack doors write this in the
/// same transaction as the manifest; attribution cannot infer a resident from
/// a caller-chosen actor id or a lease-owner string.
const RECEIPT_OWNER: SideTable<String, ReceiptOwner, Raw> =
    SideTable::new(&side_table::SKILL_RESIDENT_RECEIPT);

/// [`RECEIPT_OWNER`]'s row: the bound actor's 16-byte id.
struct ReceiptOwner(EntityId);

impl RawValue for ReceiptOwner {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let raw: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("resident receipt owner"))?;
        Ok(Self(EntityId::from_bytes(raw)?))
    }
}

pub(crate) fn bind_receipt_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    actor: &EntityId,
) -> Result<()> {
    require_executor_in_txn(&vault.store, txn, actor)?;
    let key = receipt.to_owned();
    if let Some(ReceiptOwner(held)) = RECEIPT_OWNER.get(&vault.store, txn, &key)? {
        if held != *actor {
            return Err(Error::InvalidClaimBody(
                "attempt belongs to a different actor",
            ));
        }
    } else {
        RECEIPT_OWNER.put(&vault.store, txn, &key, &ReceiptOwner(*actor))?;
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
    Ok(RECEIPT_OWNER
        .get(store, txn, &receipt.to_owned())?
        .map(|owner| owner.0))
}

/// The skills one attempt receipt's pack loaded, marked with the single byte 1.
const LOADED_SKILL: SideTable<LoadedSkillKey, [u8; 1], Raw> =
    SideTable::new(&side_table::SKILL_RESIDENT_LOADED_SKILL);

/// The marker [`LOADED_SKILL`] rows carry.
const LOADED: [u8; 1] = [1];

/// [`LOADED_SKILL`]'s key: the receipt id framed by its big-endian `u64` byte length, then the
/// skill id.
struct LoadedSkillKey {
    receipt: String,
    skill: EntityId,
}

impl LoadedSkillKey {
    fn new(receipt: &str, skill: &EntityId) -> Self {
        Self {
            receipt: receipt.to_owned(),
            skill: *skill,
        }
    }
}

impl SideKey for LoadedSkillKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        (self.receipt.len() as u64).encode_into(out);
        out.extend_from_slice(self.receipt.as_bytes());
        self.skill.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (length, rest) = bytes.split_at_checked(8)?;
        let length = usize::try_from(u64::decode_key(length)?).ok()?;
        let (receipt, skill) = rest.split_at_checked(length)?;
        Some(Self {
            receipt: std::str::from_utf8(receipt).ok()?.to_owned(),
            skill: EntityId::decode_key(skill)?,
        })
    }
}

pub(crate) fn bind_skill_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    skill: &EntityId,
) -> Result<()> {
    LOADED_SKILL.put(
        &vault.store,
        txn,
        &LoadedSkillKey::new(receipt, skill),
        &LOADED,
    )
}

pub(crate) fn receipt_loaded_skill(
    vault: &crate::Vault,
    receipt: &str,
    skill: &EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(LOADED_SKILL.get(&vault.store, &txn, &LoadedSkillKey::new(receipt, skill))? == Some(LOADED))
}
