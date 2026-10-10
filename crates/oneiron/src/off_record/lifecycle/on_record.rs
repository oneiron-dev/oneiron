//! A room on record (ARCH-0052 D5). The vault's owner, in the room, may put
//! its stretch on record ("from here on"): later turns land in this vault,
//! which is theirs. The saving stays bound to them. Every landing checks
//! again, in its own transaction, that they own this vault on a live proof
//! and are still in the room; checking only who speaks would keep saving for
//! someone who has left. Once they no longer hold, saving stops: the stretch
//! goes back off record and the room hears `saving_stopped`.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::session_overlay::SessionWriteRoute;

use super::registry::session_entry_state;
use super::room::{is_member_in_txn, post_notice};
use super::session::OffRecordSession;
use super::types::{OffRecordMode, OffRecordNoticeAct};

/// The person whose "from here on" put a room's stretch on record. Their
/// vault takes everyone's later turns, so each landing checks them again,
/// in its own transaction; checking only who speaks would keep saving for
/// someone who has left.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OnRecordSaver {
    room: EntityId,
    owner: crate::consent::AuthenticatedOwner,
}

impl OnRecordSaver {
    /// Whether, in `txn`, the saver still owns this vault on a live proof
    /// and is on the room's roster.
    pub(crate) fn holds_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        match self.owner.revalidate_as_vault_owner_in_txn(vault, txn) {
            Ok(()) => is_member_in_txn(vault, txn, self.room, self.owner.actor()),
            Err(Error::Gate(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl OffRecordSession<'_> {
    /// Flips the stretch on record for the owner: later turns are saved as
    /// they land, and the room hears a `saving_from_here` notice. In a room
    /// the owner must be on the roster and own this vault, since the flip
    /// saves everyone's later turns into it. The saving stays bound to them:
    /// every later landing checks again that they own this vault on a live
    /// proof and are still in the room, and once they are not, saving stops.
    pub fn flip_on_record_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<()> {
        let in_room = self.room()?.is_some();
        {
            let txn = self.vault.store.env.read_txn()?;
            if in_room {
                owner.revalidate_as_vault_owner_in_txn(self.vault, &txn)?;
            } else {
                owner.revalidate_in_txn(self.vault, &txn)?;
            }
        }
        let room = if in_room {
            Some(self.require_in_room(owner.actor())?)
        } else {
            None
        };
        // This handle's own entry, under one lock: the flip and its notice
        // land on the stretch the owner acted on, never on one that took its
        // name since, and a closing stretch is refused before either.
        let mut state = session_entry_state(&self.entry)?;
        let was = state.record.mode;
        super::vault_api::set_entry_mode(
            &self.entry,
            &mut state,
            &self.session_ref,
            OffRecordMode::OnRecord,
        )?;
        // A room already on record hears nothing new, and keeps its saver.
        if was != OffRecordMode::OnRecord {
            state.saver = room.map(|room| OnRecordSaver {
                room,
                owner: owner.clone(),
            });
            let at = self.vault.store.clock.now_recorded_at();
            post_notice(
                &mut state,
                OffRecordNoticeAct::SavingFromHere,
                owner.actor(),
                at,
            );
            self.entry.publish_state(&state);
        }
        Ok(())
    }

    /// The route a write lands by now and, while a room is on record, the
    /// saver its landing transaction checks again. A saver who no longer
    /// holds stops the saving here first, so the write stays off record.
    pub(crate) fn landing_route(&self) -> Result<(SessionWriteRoute, Option<OnRecordSaver>)> {
        self.lapse_saver()?;
        self.route_and_saver()
    }

    /// The saver of this stretch's room while it is on record. A durable
    /// landing reads it before its write transaction (the state lock is
    /// never taken inside one) and checks it in there.
    pub(crate) fn on_record_saver(&self) -> Result<Option<OnRecordSaver>> {
        let state = session_entry_state(&self.entry)?;
        Ok(match state.record.mode {
            OffRecordMode::OnRecord => state.saver.clone(),
            OffRecordMode::OffRecord | OffRecordMode::Anonymous => None,
        })
    }

    /// Stops the saving `saver` started: the stretch goes back off record
    /// for later turns, and the room hears that saving stopped. Saving that
    /// someone else started since is theirs, and goes on.
    pub(crate) fn stop_saving(&self, saver: &OnRecordSaver) -> Result<()> {
        let mut state = session_entry_state(&self.entry)?;
        // A closing stretch takes no more landings, so it has none to stop.
        if state.record.closing
            || state.gone
            || state.record.mode != OffRecordMode::OnRecord
            || state.saver.as_ref() != Some(saver)
        {
            return Ok(());
        }
        super::vault_api::set_entry_mode(
            &self.entry,
            &mut state,
            &self.session_ref,
            OffRecordMode::OffRecord,
        )?;
        let at = self.vault.store.clock.now_recorded_at();
        post_notice(
            &mut state,
            OffRecordNoticeAct::SavingStopped,
            saver.owner.actor(),
            at,
        );
        self.entry.publish_state(&state);
        Ok(())
    }

    /// Stops the saving when this stretch's room is on record and its saver
    /// no longer holds in a fresh snapshot; the saver that lapsed, if one did.
    pub(super) fn lapse_saver(&self) -> Result<Option<OnRecordSaver>> {
        let Some(saver) = self.on_record_saver()? else {
            return Ok(None);
        };
        if saver.holds_in_txn(self.vault, &self.vault.store.env.read_txn()?)? {
            return Ok(None);
        }
        self.stop_saving(&saver)?;
        Ok(Some(saver))
    }

    /// Refuses when this stretch's room is on record and its saver no longer
    /// holds, and stops the saving.
    pub(crate) fn require_saver(&self) -> Result<()> {
        match self.lapse_saver()? {
            Some(saver) => Err(self.saving_stopped(&saver)),
            None => Ok(()),
        }
    }

    /// One write transaction for this stretch: `write` runs only once
    /// `saver` (read before it, [`Self::on_record_saver`]) is found to hold
    /// in it. A saver who no longer holds stops the saving, and nothing is
    /// written.
    pub(crate) fn with_saver_write_txn<T>(
        &self,
        saver: Option<&OnRecordSaver>,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        let lost = std::cell::Cell::new(false);
        let written = self.vault.with_write_txn_grouped(|wtxn| {
            if let Some(saver) = saver
                && !saver.holds_in_txn(self.vault, wtxn)?
            {
                lost.set(true);
                return Err(self.saving_stopped(saver));
            }
            write(wtxn)
        });
        if lost.get()
            && let Some(saver) = saver
            && let Err(error) = self.stop_saving(saver)
        {
            tracing::warn!(error = %error, "a room on record lost its saver; the stop is deferred");
        }
        written
    }

    /// The refusal of a landing whose saver no longer holds: nothing of it
    /// was kept, and saving has stopped.
    pub(crate) fn saving_stopped(&self, saver: &OnRecordSaver) -> Error {
        Error::OffRecord(OffRecordError::OffRecordSavingStopped {
            session_ref: self.session_ref.clone(),
            saver_ref: saver.owner.actor().to_hex(),
        })
    }
}
