//! Core half of `store::skill_resident`: its store-layer items live in `oneiron_store::skill_resident` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_resident::*;

use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;
use crate::write_envelope::skill_record::SkillRecord;
use crate::write_envelope::skill_record::resident::invalid_owner;
pub(crate) use crate::write_envelope::skill_record::resident::{
    RESIDENT_PROVENANCE_KEY, resident_of,
};
use rmpv::Value;

/// Resolve a resident in the same snapshot as a skill birth or a pack stamp.
/// A replicated Candidate may wait for an out-of-order actor row, but an
/// active row cannot use the unresolved reference; a wrong-kind row never can.
pub(crate) fn require_resident_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    resident: &EntityId,
    defer_missing_candidate: bool,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, resident)? else {
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
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, actor)?
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
            && record.lifecycle_status
                != crate::write_envelope::skill_record::SkillLifecycle::Candidate
            && !crate::ports::EntityStoreRead::port_entity_present(store, txn, &resident)?
        {
            return Err(Error::Artifact(
                ArtifactError::ResidentOwnerDependencyPending,
            ));
        }
        let deferred = replicated
            && record.lifecycle_status
                == crate::write_envelope::skill_record::SkillLifecycle::Candidate;
        require_resident_in_txn(store, txn, &resident, deferred)?;
    }
    Ok(())
}

/// One attempt has one resident stamp. The scoped pack doors write this in the
/// same transaction as the manifest; attribution cannot infer a resident from
/// a caller-chosen actor id or a lease-owner string.
const RECEIPT_OWNER: SideTable<String, ReceiptOwner, Raw> =
    SideTable::new(&side_table::SKILL_RESIDENT_RECEIPT);

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
pub(crate) const LOADED_SKILL: SideTable<LoadedSkillKey, [u8; 1], Raw> =
    SideTable::new(&side_table::SKILL_RESIDENT_LOADED_SKILL);

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
