//! Live room-stretch identity for member-bound ROOM projections.

use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::session::OffRecordSessionVault;
use super::super::types::OffRecordMode;
use super::is_member_in_txn;

impl OffRecordSessionVault<'_> {
    /// The live stretches a current room member may see, in registry-key
    /// order. Published RAM reads take no registry or session-state lock.
    pub(crate) fn room_stretches_for(
        &self,
        room: EntityId,
        actor: EntityId,
    ) -> Result<Vec<(String, EntityId, OffRecordMode)>> {
        let txn = self.vault.store.env.read_txn()?;
        if !is_member_in_txn(self.vault, &txn, room, actor)? {
            return Ok(Vec::new());
        }
        let mut stretches = Vec::new();
        for key in self.vault.live_off_record_session_keys() {
            if let Some(record) = self.vault.off_record_session(&key)?
                && record.room == Some(*room.as_bytes())
                && !record.closing
            {
                stretches.push((record.session_ref, record.instance_ref, record.mode));
            }
        }
        Ok(stretches)
    }
}
