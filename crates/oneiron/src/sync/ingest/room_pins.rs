//! A room's shared pins merge record by record between a vault's machines
//! (ROOM-PINS-LWW-MERGE; RULED ROOM-PIN-CONCURRENT-UNPIN = A, Engine 17 Nov
//! 00:02: add-wins, an observed-remove set).
//!
//! A window carries a room body as one value, so of two machines that changed
//! a room's pins while apart, the window keeps one body. Ingest lands the
//! carried body with the pin records and unpinned records of both copies
//! merged ([`merge_room_pins`]): a record either copy unpinned stays out, and
//! every other record either copy holds stays in. Every other field lands as
//! carried. Where the merge holds records the carried body lacks, the window
//! owes the merged body: the import leaves a pending-mirror marker, and the
//! live mirror writes the stored body over the carrier, so the machine that
//! sent it learns this machine's records.

use std::borrow::Cow;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::RoomPin;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::store::conversation_body::{
    ConversationBody, ProjectRoom, decode, encode, merge_room_pins, validate_room_pins,
};

/// A room body in either stored shape: an ordinary room's, or a home room's.
enum RoomBody {
    Room(ConversationBody),
    Home(ProjectRoom),
}

impl RoomBody {
    /// `body` as a home room's [`ProjectRoom`], else as an ordinary room's
    /// [`ConversationBody`]. `None` for an empty body, a header-only room
    /// with no pins, and for one neither shape decodes, which the put judges
    /// as it would.
    fn decode(body: &[u8]) -> Option<Self> {
        if body.is_empty() {
            return None;
        }
        if let Ok(home) = decode::<ProjectRoom>(body) {
            return Some(Self::Home(home));
        }
        ConversationBody::from_bytes(body).ok().map(Self::Room)
    }

    /// The pin records and the unpinned records.
    fn pin_records(&self) -> (&[RoomPin], &[RoomPin]) {
        match self {
            Self::Room(body) => (&body.pins, &body.unpinned),
            Self::Home(body) => (&body.pins, &body.unpinned),
        }
    }

    /// Whether `other` is a body of the same shape.
    fn same_shape(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Room(_), Self::Room(_)) | (Self::Home(_), Self::Home(_))
        )
    }

    /// The body with `pins` and `unpinned` in place of its own, encoded as
    /// its pin door encodes it.
    fn encode_with(self, pins: Vec<RoomPin>, unpinned: Vec<RoomPin>) -> Result<Vec<u8>> {
        match self {
            Self::Room(mut body) => {
                body.pins = pins;
                body.unpinned = unpinned;
                body.to_bytes()
            }
            Self::Home(mut body) => {
                body.pins = pins;
                body.unpinned = unpinned;
                validate_room_pins(&body.pins, &body.unpinned)?;
                encode(&body)
            }
        }
    }
}

/// Whether `row` is a CONVERSATION row: a room.
fn is_room_row(row: &[u8]) -> bool {
    EntityMetadataHeader::parse(row)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_CONVERSATION)
}

/// The body `data` of the carried row `blob` at `id` as this vault admits
/// it: a room body whose pin records differ from the room body held here
/// lands with both copies' records merged ([`merge_room_pins`]), and the
/// window that carries the room owes the merged body; any other row, and a
/// room body the merge does not change, lands as it came.
///
/// # Errors
///
/// Storage errors, or a merged body that does not encode.
pub(in crate::sync) fn carried_room_pins_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
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
        .and_then(RoomBody::decode)
    else {
        return Ok(data);
    };
    let Some(carried) = RoomBody::decode(&data) else {
        return Ok(data);
    };
    if !carried.same_shape(&held) {
        return Ok(data);
    }
    let Some((pins, unpinned)) = merge_room_pins(carried.pin_records(), held.pin_records()) else {
        return Ok(data);
    };
    let merged = carried.encode_with(pins, unpinned)?;
    vault.mark_merged_carrier_in_txn(wtxn, id, blob)?;
    Ok(Cow::Owned(merged))
}
