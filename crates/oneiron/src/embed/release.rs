//! Which pending rows may leave this device, judged row by row (FIX 9486):
//! the release a host asks before it sends rows to a model off this device
//! that the engine does not see as such, a rented GPU pod behind an
//! on-device primary. A row one of its worlds keeps on this device
//! (DEC-0005) is held, and so is a row whose world cannot be read: the
//! shared resolver's `None` (an unplaced record, a NOTE whose `InWorld`
//! edges did not read) is never read as "no world". Nothing else is
//! decided here: the host's egress list and its destination are its own.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::machine_destination::PeerMachine;
use crate::settings::ReadDestination;

impl Vault {
    /// For each row of `rows`, in order, whether it may go to a model off
    /// this device that nobody proved: `true` only when no world flagged
    /// device-only keeps it and its world reads. Read once, under the flag
    /// lock, so a flag committed before it answers is one it read; a
    /// sender asks right before the bytes go and holds no answer across a
    /// later send. A row that cannot be judged is held, never the batch:
    /// the caller embeds a held row on this device.
    pub fn rows_released_off_device(&self, rows: &[EntityId]) -> Result<Vec<bool>> {
        self.rows_released_for(rows, &ReadDestination::toward(PeerMachine::Unknown))
    }

    /// [`Self::rows_released_off_device`] toward `destination`: each row is
    /// released only while no world withheld from one of its machines keeps
    /// it (FIX 5588). Nothing is held from this device.
    pub fn rows_released_for(
        &self,
        rows: &[EntityId],
        destination: &ReadDestination,
    ) -> Result<Vec<bool>> {
        let _acceptance = self.device_only_acceptance();
        let rtxn = self.store.env.read_txn()?;
        let flagged = crate::settings::device_local_worlds_for(self, &rtxn, destination)?;
        let mut released = Vec::with_capacity(rows.len());
        for row in rows {
            let free =
                match crate::settings::device_only_withholds(&self.store, &rtxn, &flagged, row) {
                    Ok(withheld) => !withheld,
                    Err(error) => {
                        tracing::warn!(
                            error_kind = ?error.kind(),
                            "a pending row's world did not read; it embeds on this device"
                        );
                        false
                    }
                };
            released.push(free);
        }
        Ok(released)
    }
}
