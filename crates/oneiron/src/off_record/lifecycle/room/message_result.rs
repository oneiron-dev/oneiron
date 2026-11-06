//! The result a room's off-record MESSAGE carries, found for someone in the
//! room outside any run (FIX 3620): the MESSAGE as the room's journal holds
//! it, admitted by the sight the room's talk copy shows its result by. Its
//! body is read through the room's own storage; nothing here reaches base.

use super::{require_sight_in_txn, visible_message};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::MessageResultAttachment;
use crate::off_record::OffRecordSession;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::session_overlay::JournalRole;

impl OffRecordSession<'_> {
    /// The result MESSAGE `message` of this stretch carries, as `actor` may
    /// see it in its room (FIX 3620): a visible MESSAGE the room's journal
    /// holds, said while `actor`'s membership showed them, the sight their
    /// copy of the talk shows it by. `None` when the stretch said no such
    /// MESSAGE, or it carries no result.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordNotInRoom`](crate::error::OffRecordError::OffRecordNotInRoom)
    /// when the stretch has no room, `actor` is not on its roster now, or
    /// their membership did not show the MESSAGE when it was said: the same
    /// refusal either way, so nothing of the room is told.
    pub(crate) fn room_message_result(
        &self,
        message: EntityId,
        actor: EntityId,
    ) -> Result<Option<MessageResultAttachment>> {
        let room = self.require_in_room(actor)?;
        let said = {
            let snapshot = self.entry.overlay.snapshot()?;
            snapshot
                .journal_entries()
                .iter()
                .find_map(|entry| match (&entry.role, &entry.op) {
                    (
                        JournalRole::MessagePartOf,
                        BatchOp::Put {
                            id,
                            entity_type,
                            data,
                            ..
                        },
                    ) if *id == message && *entity_type == ENTITY_TYPE_MESSAGE => {
                        Some((entry.occurred.start, data.clone()))
                    }
                    _ => None,
                })
        };
        let Some((at, body)) = said else {
            return Ok(None);
        };
        let txn = self.vault.store.env.read_txn()?;
        require_sight_in_txn(self.vault, &txn, &self.session_ref, room, actor, &[at])?;
        drop(txn);
        Ok(visible_message(&body)
            .ok()
            .flatten()
            .and_then(|shown| shown.result))
    }
}
