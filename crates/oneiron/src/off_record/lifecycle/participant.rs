//! A run's session handle, bound to the participant it acts as (Codex burn
//! engine-prs-01). A run in a room speaks, writes and reads there as one
//! participant, and only while they are on the room's roster: every
//! transaction its handle opens checks that again, in that transaction. Once
//! they are removed the run does nothing more in the room, while the room,
//! its saver and everyone else's runs go on. The check comes first in each
//! transaction, and each call of the run is checked again before it is
//! answered, so a removed run learns nothing of what changed in the room,
//! its saver or its own row since.

use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::room::{is_member_in_txn, not_in_room};
use super::session::OffRecordSession;

/// The participant a run's handle acts as, and the room its stretch runs in,
/// both read when the run binds. `room` is `None` for the owner's 1:1, which
/// has no roster to check.
#[derive(Clone, Copy)]
pub(super) struct RunParticipant {
    actor: EntityId,
    room: Option<EntityId>,
}

impl<'vault> OffRecordSession<'vault> {
    /// [`Self::read_composed`] with the vault the stretch reads, for a check
    /// that needs the composed view and the vault's own rows in one snapshot:
    /// a no-key search's own-entry window (FIX 6488).
    pub(crate) fn read_composed_in_vault<R>(
        &self,
        read: impl FnOnce(
            &crate::Vault,
            &crate::store::SessionStoreView<'_>,
            &heed::RoTxn<'_>,
        ) -> Result<R>,
    ) -> Result<R> {
        self.read_composed(|view, txn| read(self.vault, view, txn))
    }

    /// This stretch's handle for a run acting as `actor`. In a room `actor`
    /// must be on its roster now, and every transaction the handle reads or
    /// writes the stretch in checks that again.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordNotInRoom`](crate::error::OffRecordError::OffRecordNotInRoom)
    /// when `actor` is not in the stretch's room.
    pub(crate) fn for_participant(&self, actor: EntityId) -> Result<OffRecordSession<'vault>> {
        let bound = OffRecordSession {
            vault: self.vault,
            session_ref: self.session_ref.clone(),
            entry: Arc::clone(&self.entry),
            participant: Some(RunParticipant {
                actor,
                room: self.room()?,
            }),
        };
        bound.admit_participant()?;
        Ok(bound)
    }

    /// The actor this handle's run acts as; `None` for a handle no run is
    /// bound to.
    pub(crate) fn participant(&self) -> Option<EntityId> {
        self.participant.map(|participant| participant.actor)
    }

    /// Refuses, in a fresh snapshot, a run whose participant is no longer in
    /// its room. A run's calls make this check before they run and again
    /// before they answer, so a removed run hears only that it is not in the
    /// room, whatever has changed there since.
    pub(crate) fn admit_participant(&self) -> Result<()> {
        if matches!(self.participant, Some(RunParticipant { room: Some(_), .. })) {
            self.participant_in_txn(&self.vault.store.env.read_txn()?)?;
        }
        Ok(())
    }

    /// Refuses, in `txn`, a run whose participant is no longer in its room.
    /// A handle no run is bound to, and a 1:1, have no one to check.
    pub(super) fn participant_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        let Some(RunParticipant {
            actor,
            room: Some(room),
        }) = self.participant
        else {
            return Ok(());
        };
        if is_member_in_txn(self.vault, txn, room, actor)? {
            Ok(())
        } else {
            Err(not_in_room(&self.session_ref, actor))
        }
    }
}
