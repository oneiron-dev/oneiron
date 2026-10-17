//! Two-slot channel assignment index. Routing never ranks caller timestamps or IDs.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

use super::address::AssignmentKey;
use super::codec::decode_channel_identity_body;
use super::facts::{ChannelIdentityFacts, channel_identity_facts_in_txn};
use super::lifecycle::ChannelIdentityState;
use super::record::ChannelIdentity;

/// One assignment key's two slots: occupant id then predecessor id, zeros for an empty slot.
const SLOTS: SideTable<[u8; 32], [u8; 32], Raw> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_ASSIGNMENT);
/// Deletion evidence for a retained header-only shell, staged with slot removal.
const ERASED: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_ASSIGNMENT_ERASED);

/// The only two rows allowed to influence a mailbox route. A predecessor is
/// a retiring delegated row; it never occupies the mailbox for re-consent.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct AssignmentSlot {
    occupant: Option<EntityId>,
    predecessor: Option<EntityId>,
}

fn index_key(key: &AssignmentKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let channel = key.channel().as_bytes();
    let address = key.address_or_handle().as_bytes();
    hasher.update(&(channel.len() as u64).to_be_bytes());
    hasher.update(channel);
    hasher.update(&(address.len() as u64).to_be_bytes());
    hasher.update(address);
    *hasher.finalize().as_bytes()
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
    let Some(value) = SLOTS.get(store, txn, &index_key(key))? else {
        return Ok(AssignmentSlot::default());
    };
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
    SLOTS.put(store, txn, &index_key(key), &value)?;
    Ok(())
}

/// Read a row named by an index slot, refusing a dangling or mis-keyed index,
/// with the identity's claim facts (OF-272). The facts say which channel,
/// address and state the identity has; the row keeps custody. Facts that are
/// absent, or name another key, route nothing at this key, though the slot
/// still holds the address against reuse.
fn read_indexed_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
    id: EntityId,
) -> Result<(ChannelIdentity, Option<ChannelIdentityFacts>)> {
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
    let facts = channel_identity_facts_in_txn(store, txn, &id)?
        .filter(|facts| &AssignmentKey::of(&facts.channel, &facts.address_or_handle) == key);
    Ok((row, facts))
}

/// The live occupant or the last retiring delegated predecessor. A pending
/// occupant does not hide in-flight inbound addressed to the predecessor.
/// Each state is the identity's state head; whether a predecessor was
/// delegated is its custody's answer, never a claim's.
pub(super) fn by_assignment(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
) -> Result<Option<(EntityId, ChannelIdentity)>> {
    let slot = read_slot(store, txn, key)?;
    let occupant = match slot.occupant {
        // A deleted self-held row's hold on its address routes nothing.
        Some(id) if ERASED.get(store, txn, &id)?.is_some() => None,
        held => held
            .map(|id| read_indexed_row(store, txn, key, id).map(|(row, facts)| (id, row, facts)))
            .transpose()?,
    };
    if let Some((id, row, Some(facts))) = &occupant
        && matches!(
            facts.state,
            ChannelIdentityState::Active
                | ChannelIdentityState::Rotating
                | ChannelIdentityState::Released
                | ChannelIdentityState::Quarantine
        )
    {
        return Ok(Some((*id, row.clone())));
    }
    if let Some(id) = slot.predecessor {
        let (row, facts) = read_indexed_row(store, txn, key, id)?;
        if row.is_delegated()
            && facts.is_some_and(|facts| facts.state == ChannelIdentityState::Released)
        {
            return Ok(Some((id, row)));
        }
    }
    Ok(occupant.and_then(|(id, row, facts)| facts.map(|_| (id, row))))
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
    // A deleted self-held id still holds its own address. Coming back on
    // another one would drop that hold with its marker, and coming back
    // delegated would make it a hold the next delete frees (H102).
    if ERASED.get(store, txn, id)?.is_some() {
        let own = index_key(&key);
        for item in SLOTS.iter_from(store, &*txn, &[])? {
            let (held, slot) = item?;
            if slot[..16] == *id.as_bytes() && (held != own || next.is_delegated()) {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "channel identity assignment, custody and binding are immutable",
                )));
            }
        }
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
    write_slot(store, txn, &key, slot)?;
    // A newly admitted row at a formerly erased id is live again.
    ERASED.delete(store, txn, id)?;
    Ok(())
}

/// Clears every reference to a deleted ChannelIdentity before its body is
/// removed or soft-erased. The caller supplies the stored type while the row
/// is still readable, and stages this in the SAME write transaction as deletion.
///
/// Scan the small assignment projection rather than deriving just one key
/// from the body: a damaged body or stray second slot must not leave a dangling
/// occupant or predecessor behind. A successor in the other slot is preserved.
///
/// A self-held row holds its address forever (never-recycle), so its delete
/// keeps it as the key's occupant: the record goes, the address stays bound to
/// the deleted id, and a fresh id is refused (H102). The deletion marker below
/// is what tells readers that occupant routes nothing. A delegated row frees
/// its key, as its retirement does.
pub(crate) fn clear_assignment_for_delete(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(());
    }
    let holds_address = match store.port_entity_record(txn, id)? {
        Some(row) => match decode_channel_identity_body(&row.body) {
            Ok(row) => !row.is_delegated(),
            // A soft erase's shell kept the hold it took then.
            Err(_) => ERASED.get(store, txn, id)?.is_some(),
        },
        None => false,
    };
    let mut changed = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (key, mut slot) = item?;
        let mut touched = false;
        let (occupant, predecessor) = slot.split_at_mut(16);
        if occupant == id.as_bytes() && !holds_address {
            occupant.fill(0);
            touched = true;
        }
        if predecessor == id.as_bytes() {
            predecessor.fill(0);
            touched = true;
        }
        if touched {
            changed.push((key, slot));
        }
    }
    for (key, slot) in changed {
        if slot == [0; 32] {
            SLOTS.delete(store, txn, &key)?;
        } else {
            SLOTS.put(store, txn, &key, &slot)?;
        }
    }
    // Soft erase retains the type-index row and a metadata-only shell. This
    // marker proves that empty body was deleted rather than live corruption,
    // and on either tier marks a kept occupant as a hold. It is retired on put.
    ERASED.put(store, txn, id, &[1])?;
    Ok(())
}

/// Explicit CID-7 recovery. Only this door scans stored rows; normal routing
/// and write admission use the index. Pre-release vaults have no ABI migration.
pub(super) fn rebuild(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    // A deleted self-held row's hold has no row left to rebuild it from, so
    // recovery carries it over.
    let mut holds = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (key, slot) = item?;
        if let Some(id) = decode_id(&slot[..16])?
            && ERASED.get(store, txn, &id)?.is_some()
        {
            let mut held = [0_u8; 32];
            held[..16].copy_from_slice(id.as_bytes());
            holds.push((key, held));
        }
    }
    SLOTS.delete_from(store, txn, &[])?;
    for (key, held) in holds {
        SLOTS.put(store, txn, &key, &held)?;
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
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel identity type index kind"));
        }
        // A canonical soft deletion retains a header-only shell and a marker
        // staged in the SAME deletion transaction. Header-only corruption of a
        // live row has no marker and remains a recovery error.
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            match ERASED.get(store, txn, &id)? {
                Some([1]) => continue,
                _ => {
                    return Err(Error::CorruptedIndex(
                        "channel identity shell without deletion",
                    ));
                }
            }
        }
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
