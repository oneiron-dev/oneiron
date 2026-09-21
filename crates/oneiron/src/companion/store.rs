//! Transaction key-lookup scans over the companion-register type index.

use super::codec::decode_companion_record_body;
use super::keys::ENTITY_TYPE_COMPANION_REGISTER;
use super::model::{CompanionLifecycleEvent, CompanionRecordKey};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::Store;

pub(super) fn companion_record_id_for_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
) -> Result<Option<EntityId>> {
    key.validate()?;
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_COMPANION_REGISTER, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.lifecycle == ClaimLifecycleStatus::Active && record.key() == *key {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

pub(super) fn companion_record_any_id_for_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
) -> Result<Option<EntityId>> {
    key.validate()?;
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_COMPANION_REGISTER, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.key() == *key {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

#[derive(Debug, Default)]
pub(crate) struct CompanionRecordKeyLookup {
    pub(crate) active_id: Option<EntityId>,
    pub(crate) any_id: Option<EntityId>,
    pub(crate) retired_history_id: Option<EntityId>,
}

pub(crate) fn companion_record_key_lookup_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
    retired_lifecycle_events: Option<&[CompanionLifecycleEvent]>,
) -> Result<CompanionRecordKeyLookup> {
    key.validate()?;
    let mut lookup = CompanionRecordKeyLookup::default();
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_COMPANION_REGISTER, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.key() != *key {
            continue;
        }
        lookup.any_id.get_or_insert(id);
        if record.lifecycle == ClaimLifecycleStatus::Active {
            lookup.active_id.get_or_insert(id);
        }
        if let Some(lifecycle_events) = retired_lifecycle_events
            && record.lifecycle == ClaimLifecycleStatus::Retracted
            && record.lifecycle_events.as_slice() == lifecycle_events
        {
            lookup.retired_history_id.get_or_insert(id);
        }
        if lookup.active_id.is_some()
            && lookup.any_id.is_some()
            && (retired_lifecycle_events.is_none() || lookup.retired_history_id.is_some())
        {
            break;
        }
    }
    Ok(lookup)
}
