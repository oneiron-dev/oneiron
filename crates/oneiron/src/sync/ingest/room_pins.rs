//! A room's shared pins merge record by record between a vault's machines
//! (ROOM-PINS-LWW-MERGE; RULED ROOM-PIN-CONCURRENT-UNPIN = A, Engine 17 Nov
//! 00:02: add-wins, an observed-remove set).
//!
//! A window carries a room body as one value, so of two machines that changed
//! a room's pins while apart, the window keeps one body. Ingest lands the
//! carried body with the pin records and unpinned records of both copies
//! merged ([`merge_room_pins`]): a record either copy unpinned stays out, and
//! every other record either copy holds stays in. Only the body's `pins` and
//! `unpinned` keys change; every other key lands as carried, byte for byte,
//! in either room shape. Where the merge holds records the carried body
//! lacks, the window owes the merged body: the import leaves a pending-mirror
//! marker, and the live mirror writes the stored body over the carrier, so
//! the machine that sent it learns this machine's records.
//!
//! A row a federation peer's import brought ([`super::peer_row_in_txn`])
//! lands as it came: only the owner's own machines merge pin records.

use std::borrow::Cow;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::RoomPin;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::store::conversation_body::{
    decode, encode, invalid, merge_room_pins, validate_room_pins,
};

/// The body keys a room's pin records ride under.
const PINS_KEY: &str = "pins";
const UNPINNED_KEY: &str = "unpinned";

/// A room body's MessagePack map, with the pin records and unpinned records
/// it holds.
struct PinnedMap {
    entries: Vec<(Value, Value)>,
    pins: Vec<RoomPin>,
    unpinned: Vec<RoomPin>,
}

impl PinnedMap {
    /// `body` as a map with valid pin records under its pin keys (none where
    /// a key is absent). `None` for an empty body (a header-only room), for
    /// bytes that are no single map, and for pin keys that hold no valid
    /// records, which the put judges as it would.
    fn read(body: &[u8]) -> Option<Self> {
        if body.is_empty() {
            return None;
        }
        let mut cursor = body;
        let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
            return None;
        };
        if !cursor.is_empty() {
            return None;
        }
        let pins = records(&entries, PINS_KEY)?;
        let unpinned = records(&entries, UNPINNED_KEY)?;
        validate_room_pins(&pins, &unpinned).ok()?;
        Some(Self {
            entries,
            pins,
            unpinned,
        })
    }

    /// The map's bytes with `pins` and `unpinned` under its pin keys, each
    /// key absent while its list is empty, as the room pin doors leave it.
    fn bytes_with(mut self, pins: &[RoomPin], unpinned: &[RoomPin]) -> Result<Vec<u8>> {
        set_records(&mut self.entries, PINS_KEY, pins)?;
        set_records(&mut self.entries, UNPINNED_KEY, unpinned)?;
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(self.entries))
            .map_err(|_| invalid("body encode"))?;
        Ok(bytes)
    }
}

/// The records under `key` in `entries`: none when the key is absent,
/// `None` when its value is no list of pin records.
fn records(entries: &[(Value, Value)], key: &str) -> Option<Vec<RoomPin>> {
    let Some((_, value)) = entries.iter().find(|(name, _)| name.as_str() == Some(key)) else {
        return Some(Vec::new());
    };
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    decode::<Vec<RoomPin>>(&bytes).ok()
}

/// Puts `list` under `key` in `entries`, encoded as the pin doors encode it,
/// in place of the value there; removes the key when `list` is empty.
fn set_records(entries: &mut Vec<(Value, Value)>, key: &str, list: &[RoomPin]) -> Result<()> {
    let at = entries
        .iter()
        .position(|(name, _)| name.as_str() == Some(key));
    if list.is_empty() {
        if let Some(at) = at {
            entries.remove(at);
        }
        return Ok(());
    }
    let encoded = encode(&list)?;
    let value =
        rmpv::decode::read_value(&mut encoded.as_slice()).map_err(|_| invalid("body encode"))?;
    match at {
        Some(at) => entries[at].1 = value,
        None => entries.push((Value::from(key), value)),
    }
    Ok(())
}

/// Whether `row` is a CONVERSATION row: a room.
fn is_room_row(row: &[u8]) -> bool {
    EntityMetadataHeader::parse(row)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_CONVERSATION)
}

/// The body `data` of the carried row `blob` at `id`, in `window_key`, as
/// this vault admits it: a room body whose pin records differ from the room
/// body held here lands with both copies' records merged
/// ([`merge_room_pins`]), and the window that carries the room owes the
/// merged body. Any other row, a room body the merge does not change, and a
/// row a federation peer's import brought land as they came.
///
/// # Errors
///
/// Storage errors, or a merged body that does not encode.
pub(in crate::sync) fn carried_room_pins_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
    data: Cow<'a, [u8]>,
) -> Result<Cow<'a, [u8]>> {
    if !is_room_row(blob) {
        return Ok(data);
    }
    let Some(held) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, wtxn, id)? else {
        return Ok(data);
    };
    if !is_room_row(&held) {
        return Ok(data);
    }
    let Some(held) = held
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(PinnedMap::read)
    else {
        return Ok(data);
    };
    let Some(carried) = PinnedMap::read(&data) else {
        return Ok(data);
    };
    let Some((pins, unpinned)) = merge_room_pins(
        (&carried.pins, &carried.unpinned),
        (&held.pins, &held.unpinned),
    ) else {
        return Ok(data);
    };
    if super::peer_row_in_txn(vault, wtxn, window_key, id, blob)? {
        return Ok(data);
    }
    let merged = carried.bytes_with(&pins, &unpinned)?;
    vault.mark_merged_carrier_in_txn(wtxn, id, blob)?;
    Ok(Cow::Owned(merged))
}
