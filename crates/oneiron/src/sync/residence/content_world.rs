//! The content-world witness a home gives with each read-only copy it serves
//! (FIX 14534, Engine 11-06 08:34 call 5 = A): where the copied row sits, so
//! the owner's discard of a departed world finds the copies of that world's
//! content this install fetched, a base window's listings among them,
//! without guessing from the month. The home reads it where every read that
//! checks a world reads it ([`record_world_in`], a NOTE's live `InWorld`
//! edges); a copy fetched before a home sent one has none, and stays.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::record_scope::note_world::{NoteWorlds, note_worlds_in};
use crate::federation::record_scope::record_world_in;
use crate::ports::EntityStoreRead;
use crate::store::Store;
use crate::sync::window::Withhold;

/// Where a served copy's row sits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContentWorld {
    /// In this one world and no other, base reality included.
    Exclusive(EntityId),
    /// In base reality alone.
    Base,
    /// In more than one world, base reality counted as one.
    Shared,
    /// Not proved: a row whose world does not read, or a copy no home
    /// witnessed.
    #[default]
    Unknown,
}

/// Tags of the stored witness (`ri:c:`).
const EXCLUSIVE: u8 = 1;
const BASE: u8 = 2;
const SHARED: u8 = 3;

impl ContentWorld {
    /// The world a copy of a row in it alone belongs to.
    #[must_use]
    pub fn exclusive(self) -> Option<EntityId> {
        match self {
            Self::Exclusive(world) => Some(world),
            _ => None,
        }
    }

    /// The witness as a destination the read `withhold` serves may hold it:
    /// a world kept off that destination is never named to it.
    pub(crate) fn shown_to(self, withhold: &Withhold<'_>) -> Self {
        match (self, withhold) {
            (Self::Exclusive(world), Withhold::Worlds(withheld)) if withheld.contains(&world) => {
                Self::Unknown
            }
            (witness, _) => witness,
        }
    }

    /// The bytes a read cache keeps it as; `None` for an unknown witness,
    /// which a cache keeps as no row.
    pub(crate) fn encode(self) -> Option<Vec<u8>> {
        match self {
            Self::Exclusive(world) => {
                let mut bytes = Vec::with_capacity(17);
                bytes.push(EXCLUSIVE);
                bytes.extend_from_slice(world.as_bytes());
                Some(bytes)
            }
            Self::Base => Some(vec![BASE]),
            Self::Shared => Some(vec![SHARED]),
            Self::Unknown => None,
        }
    }

    /// The witness `bytes` keep; unknown for bytes no encoding wrote.
    pub(crate) fn decode(bytes: &[u8]) -> Self {
        match bytes {
            [EXCLUSIVE, world @ ..] => <[u8; 16]>::try_from(world)
                .ok()
                .and_then(|world| EntityId::from_bytes(world).ok())
                .map_or(Self::Unknown, Self::Exclusive),
            [BASE] => Self::Base,
            [SHARED] => Self::Shared,
            _ => Self::Unknown,
        }
    }
}

/// The witness of the stored row `id` in `txn`: a NOTE by every world its
/// live `InWorld` edges name (none is base reality), any other row where
/// [`record_world_in`] places it. A row that is not stored, does not parse
/// or proves no world is unknown.
pub(crate) fn content_world_in(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<ContentWorld> {
    let Some(raw) = store.port_entity_raw(txn, &id)? else {
        return Ok(ContentWorld::Unknown);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(ContentWorld::Unknown);
    };
    let base = crate::claim::base_world_id();
    if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
        return Ok(match note_worlds_in(store, txn, id) {
            NoteWorlds::In(worlds) => match worlds.first() {
                Some(world) if worlds.len() == 1 && world.0 == base => ContentWorld::Base,
                Some(world) if worlds.len() == 1 => ContentWorld::Exclusive(world.0),
                Some(_) => ContentWorld::Shared,
                None => ContentWorld::Unknown,
            },
            NoteWorlds::NoSingleWorld => ContentWorld::Unknown,
        });
    }
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    Ok(
        match record_world_in(store, txn, id, header.entity_type, body)? {
            Some(Some(world)) if world != base => ContentWorld::Exclusive(world),
            Some(_) => ContentWorld::Base,
            None => ContentWorld::Unknown,
        },
    )
}
