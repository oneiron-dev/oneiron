//! Two-slot channel assignment index. Routing never ranks caller timestamps or IDs.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;

use super::address::AssignmentKey;
use super::codec::decode_channel_identity_body;
use super::lifecycle::ChannelIdentityState;
use super::record::ChannelIdentity;

const PREFIX: &[u8] = b"cid_assign:v1:";

/// The only two rows allowed to influence a mailbox route. A predecessor is
/// a retiring delegated row; it never occupies the mailbox for re-consent.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct AssignmentSlot {
    occupant: Option<EntityId>,
    predecessor: Option<EntityId>,
}

fn index_key(key: &AssignmentKey) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.channel().as_bytes());
    hasher.update(&[0]);
    hasher.update(key.address_or_handle().as_bytes());
    let mut bytes = PREFIX.to_vec();
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

fn decode_id(bytes: &[u8]) -> Result<Option<EntityId>> {
    if bytes == [0; 16] {
        return Ok(None);
    }
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("channel assignment slot"))?;
    EntityId::from_bytes(raw)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("channel assignment slot"))
}

fn read_slot(store: &Store, txn: &heed::RoTxn<'_>, key: &AssignmentKey) -> Result<AssignmentSlot> {
    let Some(value) = store.vault_meta.get(txn, &index_key(key))? else {
        return Ok(AssignmentSlot::default());
    };
    if value.len() != 32 {
        return Err(Error::CorruptedIndex("channel assignment slot"));
    }
    Ok(AssignmentSlot {
        occupant: decode_id(&value[..16])?,
        predecessor: decode_id(&value[16..])?,
    })
}

fn write_slot(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &AssignmentKey,
    slot: AssignmentSlot,
) -> Result<()> {
    let mut value = [0_u8; 32];
    if let Some(id) = slot.occupant {
        value[..16].copy_from_slice(id.as_bytes());
    }
    if let Some(id) = slot.predecessor {
        value[16..].copy_from_slice(id.as_bytes());
    }
    store.vault_meta.put(txn, &index_key(key), &value)?;
    Ok(())
}

/// Read a row named by an index slot, refusing a dangling or mis-keyed index.
fn read_indexed_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
    id: EntityId,
) -> Result<ChannelIdentity> {
    let raw = store
        .port_entity_record(txn, &id)?
        .map(|row| row.encode())
        .ok_or(Error::CorruptedIndex(
            "channel assignment references absent identity",
        ))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("channel assignment header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Err(Error::CorruptedIndex("channel assignment row kind"));
    }
    let row = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if &row.assignment_key() != key {
        return Err(Error::CorruptedIndex("channel assignment key mismatch"));
    }
    Ok(row)
}

/// The live occupant or the last retiring delegated predecessor. A pending
/// occupant does not hide in-flight inbound addressed to the predecessor.
pub(super) fn by_assignment(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
) -> Result<Option<(EntityId, ChannelIdentity)>> {
    let slot = read_slot(store, txn, key)?;
    let occupant = slot
        .occupant
        .map(|id| read_indexed_row(store, txn, key, id).map(|row| (id, row)))
        .transpose()?;
    if let Some((id, row)) = &occupant
        && matches!(
            row.state(),
            ChannelIdentityState::Active
                | ChannelIdentityState::Rotating
                | ChannelIdentityState::Released
                | ChannelIdentityState::Quarantine
        )
    {
        return Ok(Some((*id, row.clone())));
    }
    if let Some(id) = slot.predecessor {
        let row = read_indexed_row(store, txn, key, id)?;
        if row.is_delegated() && row.state() == ChannelIdentityState::Released {
            return Ok(Some((id, row)));
        }
    }
    Ok(occupant)
}

/// Cheap preflight for typed writers. The put door independently maintains
/// and enforces the same slot under the write transaction.
pub(super) fn conflicts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &ChannelIdentity,
) -> Result<bool> {
    let slot = read_slot(store, txn, &row.assignment_key())?;
    Ok(row.occupies_assignment_key() && slot.occupant.is_some_and(|other| other != *id))
}

/// Enforce occupancy and stage the slot in the SAME write transaction as the
/// body. A retiring body at a fresh ID has no prior row and is refused.
pub(crate) fn maintain_assignment_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) -> Result<()> {
    let next = decode_channel_identity_body(bytes)?;
    let key = next.assignment_key();
    let prior = store.port_entity_record(txn, id)?.map(|row| row.encode());
    if let Some(raw) = &prior {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("channel assignment prior header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel assignment prior kind"));
        }
        let old = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if old.assignment_key() != key
            || old.shape() != next.shape()
            || old.grant() != next.grant()
            || old.binding() != next.binding()
        {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "channel identity assignment, custody and binding are immutable",
            )));
        }
    } else if next.is_delegated() && next.state() != ChannelIdentityState::Requested {
        return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
            "delegated identity must be born Requested",
        )));
    }
    let mut slot = read_slot(store, txn, &key)?;
    if next.occupies_assignment_key() {
        if slot.occupant.is_some_and(|other| other != *id) {
            return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
        }
        slot.occupant = Some(*id);
    } else if slot.occupant == Some(*id) {
        slot.occupant = None;
        slot.predecessor = Some(*id);
    } else if slot.predecessor != Some(*id) || prior.is_none() {
        return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
            "retired delegated identity must have occupied this assignment",
        )));
    }
    write_slot(store, txn, &key, slot)
}

/// Explicit CID-7 recovery. Only this door scans stored rows; normal routing
/// and write admission use the index. Pre-release vaults have no ABI migration.
pub(super) fn rebuild(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let stale: Vec<Vec<u8>> = store
        .vault_meta
        .prefix_iter(&*txn, PREFIX)?
        .map(|result| result.map(|(key, _)| key.to_vec()))
        .collect::<Result<_>>()?;
    for key in stale {
        store.vault_meta.delete(txn, &key)?;
    }
    let mut rows = Vec::new();
    for item in store.port_entity_ids_by_type(txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
        let id = item?;
        let raw = store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex(
                "channel identity type index dangling",
            ))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("channel identity header"))?;
        let row = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        rows.push((header.learned_at, id, row));
    }
    rows.sort_unstable_by_key(|(learned, id, _)| (*learned, *id));
    for (_, id, row) in rows {
        let key = row.assignment_key();
        let mut slot = read_slot(store, txn, &key)?;
        if row.occupies_assignment_key() {
            if slot.occupant.is_some_and(|other| other != id) {
                return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
            }
            slot.occupant = Some(id);
        } else if row.is_delegated() {
            slot.predecessor = Some(id);
        }
        write_slot(store, txn, &key, slot)?;
    }
    Ok(())
}
