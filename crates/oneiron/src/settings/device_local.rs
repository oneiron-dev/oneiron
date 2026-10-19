//! Which rows a device-local world keeps from a caller (DEC-0005): every
//! judge a door asks, built on [`device_local_worlds_for`], the one reader of
//! the flag set. Each `_for` judge reads the world settings for the machine
//! a read's rows go to ([`ReadDestination`], mesh PR2b); the others ask for
//! a destination nobody proved, as every door did before.

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::device_only::device_only_withholds;
use super::{ReadDestination, device_only_worlds_in};

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
    /// is the base world or a live WORLD row this vault holds, and its
    /// settings let it go to another machine: a world this vault does not
    /// hold, or holds only as a deleted, archived or stale row, stays, as the
    /// world settings door refuses to judge it. A call that names no world
    /// may carry any world's text, so it goes only while no world stays on
    /// this device.
    pub fn model_call_may_leave_device(&self, world: Option<EntityId>) -> Result<bool> {
        self.model_call_may_leave_for(world, &crate::claim::CallerLocality::OffDevice.into())
    }

    /// [`Self::model_call_may_leave_device`] for a model at `endpoint`: a
    /// linked machine's endpoint its connection proved is judged by that
    /// machine's own world read settings; a third-party or unproved endpoint
    /// is a destination nobody proved (mesh PR2b). Never the requester's
    /// proof: the model is a recipient of its own.
    pub fn model_call_may_leave_for(
        &self,
        world: Option<EntityId>,
        endpoint: &ReadDestination,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let flagged = device_local_worlds_for(self, &rtxn, endpoint)?;
        let Some(world) = world else {
            return Ok(flagged.is_empty());
        };
        if flagged.contains(&world) {
            return Ok(false);
        }
        if world == crate::claim::base_world_id() {
            return Ok(true);
        }
        if self.get_entity_type_in_txn(&rtxn, &world)? != Some(crate::registry::ENTITY_TYPE_WORLD) {
            return Ok(false);
        }
        let visibility =
            crate::ports::TombstoneStoreRead::port_deletion_state(&self.store, &rtxn, &world)?;
        Ok(!(visibility.deleted || visibility.archived || visibility.stale))
    }

    /// Whether a device-local world keeps `id` on this device, so no caller
    /// off it reads the row (DEC-0005). A row whose world cannot be read is
    /// kept too.
    pub fn device_local_keeps(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        device_local_keeps_in(self, &rtxn, id)
    }

    /// [`Self::device_local_keeps`] for a read toward `destination`: whether
    /// the world settings keep `id` from one of the machines its rows go to.
    /// Nothing is kept from a caller on this device.
    pub fn device_local_keeps_for(
        &self,
        id: &EntityId,
        destination: &ReadDestination,
    ) -> Result<bool> {
        if !destination.is_off_device() {
            return Ok(false);
        }
        let rtxn = self.store.env.read_txn()?;
        let flagged = device_local_worlds_for(self, &rtxn, destination)?;
        device_local_keeps_among(&self.store, &rtxn, &flagged, id)
    }

    /// The rows of `ids` a caller off this device may count or name: each one
    /// no device-local world keeps ([`Self::device_local_keeps`]), judged in
    /// one read.
    pub fn off_device_readable(&self, ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
        self.off_device_readable_for(ids, &crate::claim::CallerLocality::OffDevice.into())
    }

    /// [`Self::off_device_readable`] for a read toward `destination`, judged
    /// in one read: each row no world withheld from one of its machines
    /// keeps. Every row on this device.
    pub fn off_device_readable_for(
        &self,
        ids: Vec<EntityId>,
        destination: &ReadDestination,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let flagged = device_local_worlds_for(self, &rtxn, destination)?;
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
/// of: every world the world settings withhold from a machine nobody proved,
/// off this device; none on it. A door that knows the machine at the other
/// end asks [`device_local_worlds_for`].
pub(crate) fn device_local_worlds_at(
    vault: &Vault,
    txn: &RoTxn<'_>,
    locality: crate::claim::CallerLocality,
) -> Result<std::collections::BTreeSet<EntityId>> {
    device_local_worlds_for(vault, txn, &locality.into())
}

/// The worlds whose rows a read toward `destination` reads nothing of: every
/// world the world settings withhold from one of the machines its rows go
/// to, each proof judged in `txn`; none on this device (mesh PR2b).
pub(crate) fn device_local_worlds_for(
    vault: &Vault,
    txn: &RoTxn<'_>,
    destination: &ReadDestination,
) -> Result<std::collections::BTreeSet<EntityId>> {
    device_only_worlds_in(vault, txn, destination)
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
