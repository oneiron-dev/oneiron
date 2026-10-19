//! The device-local pass of a capped Graph-FS scan (DEC-0005). Off this
//! device a scan steps past every row a device-local world keeps before the
//! row takes a place in its cap, so the cap never stops on one and no
//! continuation hints that such rows filled it. Each world is judged for
//! the machine the reader's rows go to (mesh PR2b), in the scan's snapshot.

use heed::RoTxn;

use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{
    EdgeDirection, EdgeStoreRead as _, EntityStoreRead as _, EntityTime, PortRows, TimelineQuery,
};

use super::model::GraphFsResolver;

impl<'vault> GraphFsResolver<'_, 'vault> {
    /// The entity timeline `query` reads, as this reader's capped scans
    /// count it.
    pub(super) fn admitted_timeline<'a>(
        &self,
        rtxn: &'a RoTxn<'_>,
        query: TimelineQuery,
    ) -> Result<PortRows<'a, EntityTime>>
    where
        'vault: 'a,
    {
        let rows = self
            .scoped_read
            .vault()
            .store
            .port_entity_timeline(rtxn, query)?;
        self.device_admitted(rtxn, rows, |time: &EntityTime| time.id)
    }

    /// The edges at `center` after `after`, as this reader's capped scans
    /// count them: each by the row at its far end.
    pub(super) fn admitted_edges<'a>(
        &self,
        rtxn: &'a RoTxn<'_>,
        center: &EntityId,
        direction: EdgeDirection,
        after: Option<(u8, EntityId)>,
    ) -> Result<PortRows<'a, EdgeInfo>>
    where
        'vault: 'a,
    {
        let rows = self
            .scoped_read
            .vault()
            .store
            .port_edge_cursor(rtxn, center, direction, after)?;
        self.device_admitted(rtxn, rows, |edge: &EdgeInfo| edge.target)
    }

    /// `rows` less every one whose row `id_of` names a device-local world
    /// keeps from this reader: all of them on this device, or while no
    /// world is flagged.
    fn device_admitted<'a, T: 'a>(
        &self,
        rtxn: &'a RoTxn<'_>,
        rows: PortRows<'a, T>,
        id_of: fn(&T) -> EntityId,
    ) -> Result<PortRows<'a, T>>
    where
        'vault: 'a,
    {
        let store = &self.scoped_read.vault().store;
        let withheld = crate::settings::device_local_worlds_for(
            self.scoped_read.vault(),
            rtxn,
            self.scoped_read.actor_key().destination(),
        )?;
        if withheld.is_empty() {
            return Ok(rows);
        }
        Ok(Box::new(rows.filter_map(move |row| {
            let kept = row.as_ref().map_or(Ok(false), |found| {
                crate::settings::device_local_keeps_among(store, rtxn, &withheld, &id_of(found))
            });
            match kept {
                Ok(true) => None,
                Ok(false) => Some(row),
                Err(error) => Some(Err(error)),
            }
        })))
    }

    /// Whether a world withheld from a machine this reader's rows go to
    /// keeps `world`'s own row, judged in `rtxn`: never on this device.
    pub(super) fn device_keeps_world(&self, rtxn: &RoTxn<'_>, world: &EntityId) -> Result<bool> {
        let vault = self.scoped_read.vault();
        let destination = self.scoped_read.actor_key().destination();
        if !destination.is_off_device() {
            return Ok(false);
        }
        let withheld = crate::settings::device_local_worlds_for(vault, rtxn, destination)?;
        crate::settings::device_local_keeps_among(&vault.store, rtxn, &withheld, world)
    }
}
