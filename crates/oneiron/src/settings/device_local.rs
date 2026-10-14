//! Which rows a device-local world keeps from a caller (DEC-0005): every
//! judge a door asks, built on [`device_local_worlds_at`], the one reader of
//! the flag set.

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::store::ManifestDbs;

use super::device_only_worlds_in;

impl Vault {
    /// Whether every row of `rows` may leave this device now: none is one a
    /// device-local world keeps (DEC-0005), or whose world cannot be read.
    /// Read under the flag lock, so a flag committed before it answers is
    /// one it read. A sender asks right before the bytes go, and holds no
    /// answer across a later send.
    #[cfg(feature = "sync")]
    pub fn rows_may_leave_device(&self, rows: &[EntityId]) -> Result<bool> {
        let _acceptance = self.device_only_acceptance();
        let rtxn = self.store.env.read_txn()?;
        let flagged =
            device_local_worlds_at(&self.store, &rtxn, crate::claim::CallerLocality::OffDevice)?;
        for row in rows {
            match device_only_withholds(&self.store, &rtxn, &flagged, row) {
                Ok(false) => {}
                Ok(true) | Err(Error::CorruptedIndex(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    /// Whether `world` is flagged device-only on this device: one whose rows
    /// a caller off it never reads.
    pub fn world_is_device_only(&self, world: EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(
            device_local_worlds_at(&self.store, &rtxn, crate::claim::CallerLocality::OffDevice)?
                .contains(&world),
        )
    }

    /// Whether a device-local world keeps `id` on this device, so no caller
    /// off it reads the row (DEC-0005). A row whose world cannot be read is
    /// kept too.
    pub fn device_local_keeps(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        device_local_keeps_in(&self.store, &rtxn, id)
    }

    /// The rows of `ids` a caller off this device may count or name: each one
    /// no device-local world keeps ([`Self::device_local_keeps`]), judged in
    /// one read.
    pub fn off_device_readable(&self, ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let flagged =
            device_local_worlds_at(&self.store, &rtxn, crate::claim::CallerLocality::OffDevice)?;
        let mut readable = Vec::with_capacity(ids.len());
        for id in ids {
            if !device_local_keeps_among(&self.store, &rtxn, &flagged, &id)? {
                readable.push(id);
            }
        }
        Ok(readable)
    }
}

/// [`Vault::device_local_keeps`], read in the caller's transaction.
pub(crate) fn device_local_keeps_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let flagged = device_local_worlds_at(store, txn, crate::claim::CallerLocality::OffDevice)?;
    device_local_keeps_among(store, txn, &flagged, id)
}

/// The device-local worlds whose rows a caller at `locality` reads nothing
/// of: every flagged one off this device, none on it.
pub(crate) fn device_local_worlds_at(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    locality: crate::claim::CallerLocality,
) -> Result<std::collections::BTreeSet<EntityId>> {
    match locality {
        crate::claim::CallerLocality::OffDevice => device_only_worlds_in(store, txn),
        crate::claim::CallerLocality::OnDevice => Ok(std::collections::BTreeSet::new()),
    }
}

/// [`device_local_keeps_in`] against `flagged`, the flag set read once in
/// `txn` for many rows. `store` is the target the row is read from: a room's
/// overlay ∪ base judges the rows the room stages as well.
pub(crate) fn device_local_keeps_among(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &std::collections::BTreeSet<EntityId>,
    id: &EntityId,
) -> Result<bool> {
    match device_only_withholds(store, txn, flagged, id) {
        Err(Error::CorruptedIndex(_)) => Ok(true),
        held => held,
    }
}

/// Whether a device-only world keeps `id` on this device: the flagged WORLD
/// row itself, a CLAIM whose `worldId` is flagged (an erased or purged one by
/// the world address its deletion kept), a NOTE with a stored `InWorld` edge
/// to a flagged world, or any other record the shared resolver
/// (`record_scope::record_world_in`) places in a flagged world: a TASK where
/// its birth stamp settled it. A record it cannot place is kept.
pub(crate) fn device_only_withholds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &std::collections::BTreeSet<EntityId>,
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
    flagged: &std::collections::BTreeSet<EntityId>,
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
        return claim_in_flagged_world(store, txn, flagged, id, None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    match header.entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            claim_in_flagged_world(store, txn, flagged, id, Some(raw))
        }
        crate::registry::ENTITY_TYPE_NOTE => {
            for edge in store.port_edges(
                txn,
                id,
                EdgeDirection::Out,
                Some(crate::edge::EdgeKind::InWorld),
                None,
            )? {
                if flagged.contains(&edge?.target) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        kind => {
            let body = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .unwrap_or_default();
            Ok(
                crate::federation::record_scope::record_world_in(store, txn, *id, kind, body)?
                    .is_none_or(|world| world.is_some_and(|world| flagged.contains(&world))),
            )
        }
    }
}

/// A CLAIM's world from its stored body. An erased claim keeps only its
/// header (its row fenced as deleted), and a purged one nothing; its deletion
/// kept the world window's address (`m:dw:`, `<month>@<world>`). A body that
/// cannot be read, a bare header on a row not fenced as deleted, or an
/// address that is not a world window's is an error, never portability: the
/// world is unknown.
fn claim_in_flagged_world(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &std::collections::BTreeSet<EntityId>,
    id: &EntityId,
    raw: Option<&[u8]>,
) -> Result<bool> {
    let unknown = || Error::CorruptedIndex("device-only claim world");
    if let Some(raw) = raw {
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .unwrap_or_default();
        if !body.is_empty() {
            let body = crate::claim::decode_claim_body(body, true).map_err(|_| unknown())?;
            return Ok(body.world.is_some_and(|world| flagged.contains(&world)));
        }
        if !crate::deletion::row_deletion_marked(store, txn, id, Some(raw))? {
            return Err(unknown());
        }
    }
    let Some(label) = store
        .sync_state()
        .get(txn, &format!("m:dw:{}", id.to_hex()))?
    else {
        return Ok(false);
    };
    let world = std::str::from_utf8(&label)
        .ok()
        .filter(|label| crate::deletion::parse_window_label(label).is_some())
        .and_then(|label| label.split_once('@'))
        .and_then(|(_, world)| EntityId::from_hex(world).ok())
        .ok_or(Error::CorruptedIndex("deletion window address"))?;
    Ok(flagged.contains(&world))
}
