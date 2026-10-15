//! Which rows a device-local world keeps from a caller (DEC-0005): every
//! judge a door asks, built on [`device_local_worlds_at`], the one reader of
//! the flag set.

use heed::RoTxn;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::device_only::device_only_withholds;
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
        let flagged = device_local_worlds_at(self, &rtxn, crate::claim::CallerLocality::OffDevice)?;
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
            device_local_worlds_at(self, &rtxn, crate::claim::CallerLocality::OffDevice)?
                .contains(&world),
        )
    }

    /// Whether a model call that names `world`, or none, may go to a model
    /// off this device (world privacy, "Models"). A named world goes when it
    /// is the base world or a WORLD row this vault holds, and its settings
    /// let it go to another machine: a world this vault does not hold stays,
    /// since nothing here can judge it. A call that names no world may carry
    /// any world's text, so it goes only while no world stays on this device.
    pub fn model_call_may_leave_device(&self, world: Option<EntityId>) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let flagged = device_local_worlds_at(self, &rtxn, crate::claim::CallerLocality::OffDevice)?;
        let Some(world) = world else {
            return Ok(flagged.is_empty());
        };
        if flagged.contains(&world) {
            return Ok(false);
        }
        if world == crate::claim::base_world_id() {
            return Ok(true);
        }
        let kind = self
            .store
            .entities
            .get(&rtxn, world.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(raw).map(|header| header.entity_type));
        Ok(kind == Some(crate::registry::ENTITY_TYPE_WORLD))
    }

    /// Whether a device-local world keeps `id` on this device, so no caller
    /// off it reads the row (DEC-0005). A row whose world cannot be read is
    /// kept too.
    pub fn device_local_keeps(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        device_local_keeps_in(self, &rtxn, id)
    }

    /// The rows of `ids` a caller off this device may count or name: each one
    /// no device-local world keeps ([`Self::device_local_keeps`]), judged in
    /// one read.
    pub fn off_device_readable(&self, ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let flagged = device_local_worlds_at(self, &rtxn, crate::claim::CallerLocality::OffDevice)?;
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
pub(crate) fn device_local_keeps_in(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let flagged = device_local_worlds_at(vault, txn, crate::claim::CallerLocality::OffDevice)?;
    device_local_keeps_among(&vault.store, txn, &flagged, id)
}

/// The device-local worlds whose rows a caller at `locality` reads nothing
/// of: every world the world settings withhold from another machine, off
/// this device; none on it.
pub(crate) fn device_local_worlds_at(
    vault: &Vault,
    txn: &RoTxn<'_>,
    locality: crate::claim::CallerLocality,
) -> Result<std::collections::BTreeSet<EntityId>> {
    match locality {
        crate::claim::CallerLocality::OffDevice => device_only_worlds_in(vault, txn),
        crate::claim::CallerLocality::OnDevice => Ok(std::collections::BTreeSet::new()),
    }
}

/// [`device_local_keeps_in`] against `flagged`, the flag set read once in
/// `txn` for many rows. `store` is the target the row is read from: a room's
/// overlay ∪ base judges the rows the room stages as well.
pub(crate) fn device_local_keeps_among(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    flagged: &std::collections::BTreeSet<EntityId>,
    id: &EntityId,
) -> Result<bool> {
    match device_only_withholds(store, txn, flagged, id) {
        Err(Error::CorruptedIndex(_)) => Ok(true),
        held => held,
    }
}
