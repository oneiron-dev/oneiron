//! What a world flagged device-only keeps on this device, row by row
//! (DEC-0005). Every export door asks [`device_only_withholds`] against the
//! flags it read.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EdgeDirection, EdgeStoreRead, TombstoneStoreRead};
use crate::store::{ManifestDbs, Store};

/// The worlds whose words a record carries. `unknown` where one of them
/// cannot be named, which keeps the record home while any world is flagged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CarriedWorlds {
    pub(crate) worlds: BTreeSet<EntityId>,
    pub(crate) unknown: bool,
}

impl CarriedWorlds {
    /// Where a deletion's world window address puts a row: an address that
    /// names no world leaves it unknown.
    fn from_address(world: Option<EntityId>) -> Self {
        Self {
            unknown: world.is_none(),
            worlds: world.into_iter().collect(),
        }
    }

    fn kept_by(&self, flagged: &BTreeSet<EntityId>) -> bool {
        self.unknown || !self.worlds.is_disjoint(flagged)
    }

    /// Adds `other`; whether that grew the set.
    pub(crate) fn absorb(&mut self, other: &Self) -> bool {
        let before = (self.worlds.len(), self.unknown);
        self.worlds.extend(other.worlds.iter().copied());
        self.unknown |= other.unknown;
        before != (self.worlds.len(), self.unknown)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = vec![u8::from(self.unknown)];
        for world in &self.worlds {
            out.extend_from_slice(world.as_bytes());
        }
        out
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        let corrupt = || Error::CorruptedIndex("withdrawn worlds");
        let (&unknown, ids) = raw.split_first().ok_or_else(corrupt)?;
        if unknown > 1 || ids.len() % 16 != 0 {
            return Err(corrupt());
        }
        let worlds = ids
            .chunks_exact(16)
            .map(|id| EntityId::from_bytes(id.try_into().map_err(|_| corrupt())?))
            .collect::<Result<_>>()?;
        Ok(Self {
            worlds,
            unknown: unknown == 1,
        })
    }
}

/// Whether a device-only world keeps `id` on this device: the flagged WORLD
/// row itself, a CLAIM whose `worldId` is flagged (an erased or purged one by
/// the world address its deletion kept), a NOTE with a stored `InWorld` edge
/// to a flagged world, or an epoch SUMMARY born in one. An epoch SUMMARY
/// carries the words of every record it was written from, so it stays too
/// when a flagged world keeps any of them, through any nested epoch, or one
/// its withdrawal recorded, and while any world is flagged when it cannot
/// prove where it was born. Any other record sits where the shared resolver
/// (`record_scope::record_world_in`) places it, a TASK where its birth stamp
/// settled it, and one it cannot place is kept. Nothing is read while no
/// world is flagged. `store` is the target the row is read from: a room's
/// overlay ∪ base judges the rows the room stages as well.
pub(crate) fn device_only_withholds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    id: &EntityId,
) -> Result<bool> {
    if flagged.is_empty() {
        return Ok(false);
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?;
    device_only_withholds_raw(store, txn, flagged, id, raw.as_deref())
}

/// [`device_only_withholds`] judged on `raw`, the revision of `id` a door
/// serves (`None` when no row is stored): a CLAIM by the world that revision
/// names.
pub(crate) fn device_only_withholds_raw(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    id: &EntityId,
    raw: Option<&[u8]>,
) -> Result<bool> {
    if flagged.is_empty() {
        return Ok(false);
    }
    if flagged.contains(id) {
        return Ok(true);
    }
    let Some(raw) = raw else {
        // A purged row's words stay in window history until the historical
        // sweep runs; a purged epoch summary's record says where they sat.
        let mut gone = CarriedWorlds {
            worlds: claim_world(store, txn, id, None)?.into_iter().collect(),
            unknown: false,
        };
        if let Some(withdrawn) = crate::ports::withdrawn_worlds_in(store, txn, id)? {
            gone.absorb(&withdrawn);
        }
        return Ok(gone.kept_by(flagged));
    };
    let mut sources = Vec::new();
    let mut carried = row_worlds(store, txn, id, raw, &mut sources)?;
    carried.absorb(&sources_worlds(store, txn, BTreeSet::from([*id]), sources)?);
    Ok(carried.kept_by(flagged))
}

/// The worlds whose words the stored row `id` carries: where it sits and, for
/// an epoch SUMMARY, where each record it was written from sits and what its
/// own withdrawal recorded. A deletion records them on every epoch summary it
/// withdraws, before the row, its stamp and its edges go.
pub(crate) fn carried_worlds_in(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<CarriedWorlds> {
    sources_worlds(store, txn, BTreeSet::new(), vec![*id])
}

/// The worlds a summary minted from the deleted or withdrawn record `id`
/// copies words of. A SUMMARY whose body a deletion took no longer says where
/// it sat (its stamp went with its words), yet the run read them before: they
/// are unknown. Its erase already captured them for every summary written from
/// it before, so only a mint asks this.
pub(crate) fn minted_worlds_in(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<CarriedWorlds> {
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        && raw.first() == Some(&crate::registry::ENTITY_TYPE_SUMMARY)
        && raw.len() <= ENTITY_METADATA_HEADER_LEN
    {
        return Ok(CarriedWorlds {
            worlds: BTreeSet::new(),
            unknown: true,
        });
    }
    carried_worlds_in(store, txn, id)
}

/// The worlds of `pending` and of every record each was written from, each
/// read once, nested epochs included. A row this device cannot read (one that
/// does not parse, or one gone while an edge to it stays, which no deletion
/// leaves) makes them unknown; a deleted world CLAIM sits where the world
/// window address its deletion kept says.
fn sources_worlds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    mut seen: BTreeSet<EntityId>,
    mut pending: Vec<EntityId>,
) -> Result<CarriedWorlds> {
    let mut carried = CarriedWorlds::default();
    while let Some(source) = pending.pop() {
        if !seen.insert(source) {
            continue;
        }
        let found = match crate::ports::EntityStoreRead::port_entity_raw(store, txn, &source)? {
            Some(raw) => row_worlds(store, txn, &source, &raw, &mut pending),
            None => deletion_world(store, txn, &source).map(CarriedWorlds::from_address),
        };
        match found {
            Ok(found) => {
                carried.absorb(&found);
            }
            Err(Error::CorruptedIndex(_)) => carried.unknown = true,
            Err(error) => return Err(error),
        }
    }
    Ok(carried)
}

/// Where the stored row `id` (`raw`) sits: the WORLD row in itself, a CLAIM in
/// its body's world, a NOTE in each world it has an `InWorld` edge to, a
/// SUMMARY where `record_world_in` places it (unknown for an epoch it cannot
/// place, never base) and in every world its withdrawal recorded. An epoch
/// SUMMARY's `DerivedFrom` sources go to `sources`.
fn row_worlds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    sources: &mut Vec<EntityId>,
) -> Result<CarriedWorlds> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let mut carried = CarriedWorlds::default();
    match header.entity_type {
        crate::registry::ENTITY_TYPE_WORLD => {
            carried.worlds.insert(*id);
        }
        crate::registry::ENTITY_TYPE_CLAIM => {
            carried
                .worlds
                .extend(claim_world(store, txn, id, Some(raw))?);
        }
        crate::registry::ENTITY_TYPE_NOTE => {
            for edge in
                store.port_edges(txn, id, EdgeDirection::Out, Some(EdgeKind::InWorld), None)?
            {
                carried.worlds.insert(edge?.target);
            }
        }
        crate::registry::ENTITY_TYPE_SUMMARY => {
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            // An epoch whose pointer no head stands for may carry any world's
            // words (Astra 1384e).
            let epoch = crate::compaction::stored_epoch_in(store, txn, id, body)?;
            carried.unknown |= epoch == crate::compaction::StoredEpoch::Unresolved;
            if epoch.may_be() {
                for edge in store.port_edges(
                    txn,
                    id,
                    EdgeDirection::Out,
                    Some(EdgeKind::DerivedFrom),
                    None,
                )? {
                    sources.push(edge?.target);
                }
            }
            // An epoch that cannot prove where it was born (a replica, which
            // arrives without its stamp, or one minted before stamps) may
            // carry any world's words.
            match crate::federation::record_scope::record_world_in(
                store,
                txn,
                *id,
                header.entity_type,
                body,
            )? {
                Some(world) => carried.worlds.extend(world),
                None => carried.unknown = true,
            }
            if let Some(withdrawn) = crate::ports::withdrawn_worlds_in(store, txn, id)? {
                carried.absorb(&withdrawn);
            }
        }
        // Any other record sits where the shared resolver places it: a TASK
        // where its birth stamp settled it. One it cannot place is kept.
        kind => {
            let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
            match crate::federation::record_scope::record_world_in(store, txn, *id, kind, body)? {
                Some(world) => carried.worlds.extend(world),
                None => carried.unknown = true,
            }
        }
    }
    Ok(carried)
}

/// A CLAIM's world from its stored body. An erased claim keeps only its
/// header (its row fenced as deleted), and a purged one nothing; its deletion
/// kept the world window's address. A body that cannot be read, or a bare
/// header on a row not fenced as deleted, is an error, never portability: the
/// world is unknown.
fn claim_world(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: Option<&[u8]>,
) -> Result<Option<EntityId>> {
    let unknown = || Error::CorruptedIndex("device-only claim world");
    if let Some(raw) = raw {
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        if !body.is_empty() {
            let body = crate::claim::decode_claim_body(body, true).map_err(|_| unknown())?;
            return Ok(body.world);
        }
        if !crate::deletion::row_deletion_marked(store, txn, id, Some(raw))? {
            return Err(unknown());
        }
    }
    deletion_world(store, txn, id)
}

/// The world a deleted world CLAIM sat in, by the window address its deletion
/// kept (`m:dw:`, `<month>@<world>`); `None` where no deletion kept one. An
/// address that is not a world window's is an error: the world is unknown.
fn deletion_world(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(label) = store.port_deletion_marker(txn, DeletionMarker::WindowAddress, id)? else {
        return Ok(None);
    };
    std::str::from_utf8(&label)
        .ok()
        .filter(|label| crate::deletion::parse_window_label(label).is_some())
        .and_then(|label| label.split_once('@'))
        .and_then(|(_, world)| EntityId::from_hex(world).ok())
        .map(Some)
        .ok_or(Error::CorruptedIndex("deletion window address"))
}
