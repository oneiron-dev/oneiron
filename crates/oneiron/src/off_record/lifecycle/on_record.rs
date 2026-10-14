//! A room on record (ARCH-0052 D5). The vault's owner, in the room, may put
//! its stretch on record ("from here on"): later turns land in this vault,
//! which is theirs. The saving stays bound to them. Every landing checks
//! again, in its own transaction, that they own this vault on a live proof
//! and are still in the room, in the membership they saved in; checking only
//! who speaks would keep saving for someone who has left. Once they no longer
//! hold, saving stops: the stretch goes back off record and the room hears
//! `saving_stopped`. Joining the room again does not restart it.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::session_overlay::{RouteTarget, SessionWriteRoute};

use super::registry::session_entry_state;
use super::room::{Hearing, is_member_in_txn, post_notice};
use super::session::OffRecordSession;
use super::types::{OffRecordMode, OffRecordNoticeAct};

/// The person whose "from here on" put a room's stretch on record. Their
/// vault takes everyone's later turns, so each landing checks them again,
/// in its own transaction; checking only who speaks would keep saving for
/// someone who has left.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OnRecordSaver {
    room: EntityId,
    /// Where the join that opened the membership they put the room on record
    /// in sits in the room's ledger. The saving is bound to that membership.
    joined: u64,
    owner: crate::consent::AuthenticatedOwner,
}

impl OnRecordSaver {
    /// Whether, in `txn`, the saver still owns this vault on a live proof
    /// and is still in the room in the membership they saved in. Leaving
    /// ends the saving for good: joining again does not bring it back.
    pub(crate) fn holds_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        match self.owner.revalidate_as_vault_owner_in_txn(vault, txn) {
            Ok(()) => Ok(is_member_in_txn(vault, txn, self.room, self.owner.actor())?
                && vault.current_join_in_txn(txn, self.room, self.owner.actor())?
                    == Some(self.joined)),
            Err(Error::Gate(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// A landing's check of the saver of a room on record. The landing runs it
/// in its write transaction, and one that finds the saver no longer holds
/// is refused. Once the check drops, after that transaction, the saving
/// stops: stopping takes the session state lock, which is never taken under
/// the writer. The lapse is atomic so a retrieval's door, which holds one,
/// can be shared with the async handler that runs it.
pub(crate) struct SaverCheck<'s, 'vault> {
    session: &'s OffRecordSession<'vault>,
    saver: OnRecordSaver,
    lapsed: AtomicBool,
}

impl SaverCheck<'_, '_> {
    /// Refuses unless, in `txn`, the saver still holds.
    pub(crate) fn in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        if self.saver.holds_in_txn(self.session.vault, txn)? {
            return Ok(());
        }
        self.lapsed.store(true, Ordering::Relaxed);
        Err(self.session.saving_stopped(&self.saver))
    }
}

impl Drop for SaverCheck<'_, '_> {
    fn drop(&mut self) {
        // The refusal stands whatever the stop meets; the next landing tries
        // again.
        if self.lapsed.load(Ordering::Relaxed)
            && let Err(error) = self.session.stop_saving(&self.saver)
        {
            tracing::warn!(error = %error, "a room on record lost its saver; the stop is deferred");
        }
    }
}

/// A base write's first step in its transaction: a run's write comes from a
/// participant still in the room, in a room on record its saver still
/// holds, and the route it was taken on still stands.
pub(super) struct Landing<'r, 's, 'vault> {
    pub(super) route: &'r SessionWriteRoute,
    session: &'s OffRecordSession<'vault>,
    saver: Option<SaverCheck<'s, 'vault>>,
}

impl Landing<'_, '_, '_> {
    pub(super) fn in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.session
            .participant_and_saver_in_txn(self.saver.as_ref(), txn)?;
        // The route is checked again here, not only before the writer: a
        // room that went off record, or whose saving stopped, while this
        // write waited for the writer keeps nothing of it.
        self.route.revalidate()
    }

    /// An overlay write's first step in its transaction: the route still
    /// stands and a run's write comes from a participant still in the room.
    pub(super) fn in_overlay_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.session.participant_in_txn(txn)?;
        self.route.revalidate()
    }
}

impl<'vault> OffRecordSession<'vault> {
    /// Flips the stretch on record for the owner: later turns are saved as
    /// they land, and the room hears a `saving_from_here` notice. In a room
    /// the owner must be on the roster and own this vault, since the flip
    /// saves everyone's later turns into it. The saving stays bound to them:
    /// every later landing checks again that they own this vault on a live
    /// proof and are still in the room, in the membership they flipped in.
    /// Once they are not, saving stops, and only a new flip starts it again.
    ///
    /// Alone or in a room, there is no flip on record without the proof
    /// (H203):
    ///
    /// ```compile_fail
    /// fn flip(session: &oneiron::off_record::OffRecordSession<'_>) {
    ///     let _ = session.flip_on_record();
    /// }
    /// ```
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
            let room = self.require_in_room(owner.actor())?;
            let joined = self
                .vault
                .current_join_in_txn(&self.vault.store.env.read_txn()?, room, owner.actor())?
                .ok_or_else(|| {
                    Error::OffRecord(OffRecordError::OffRecordNotInRoom {
                        session_ref: self.session_ref.clone(),
                        actor_ref: owner.actor().to_hex(),
                    })
                })?;
            Some((room, joined))
        } else {
            None
        };
        // A standing saver who no longer holds has stopped saving, so this
        // flip puts the room back on record under this owner's proof.
        self.lapse_saver()?;
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
            state.saver = room.map(|(room, joined)| OnRecordSaver {
                room,
                joined,
                owner: owner.clone(),
            });
            let hearing = Hearing::now(self.vault, state.record.room);
            post_notice(
                &mut state,
                OffRecordNoticeAct::SavingFromHere,
                owner.actor(),
                hearing,
            );
            self.entry.publish_state(&state);
        }
        Ok(())
    }

    /// The route a write lands by now and, while a room is on record, the
    /// saver its landing transaction checks again. A saver who no longer
    /// holds stops the saving here first, so the write stays off record.
    pub(crate) fn landing_route(
        &self,
    ) -> Result<(SessionWriteRoute, Option<SaverCheck<'_, 'vault>>)> {
        self.lapse_saver()?;
        let (route, saver) = self.route_and_saver()?;
        Ok((route, saver.map(|saver| self.check_saver(saver))))
    }

    /// The check a write on `route`, a route taken earlier, runs in its
    /// transaction while this stretch's room is on record; `None` otherwise.
    /// The saver is the one `route` lands under: it is read with `route`
    /// checked, under one lock, so saving that stopped since refuses here
    /// rather than reading as no saver at all. Only the saver's door puts a
    /// room on record, so a room's base route with no saver refuses too.
    pub(crate) fn saver_check_for(
        &self,
        route: &SessionWriteRoute,
    ) -> Result<Option<SaverCheck<'_, 'vault>>> {
        let state = session_entry_state(&self.entry)?;
        route.revalidate()?;
        if route.target() != RouteTarget::Base || state.record.room.is_none() {
            return Ok(None);
        }
        let saver = state
            .saver
            .clone()
            .ok_or(Error::InvariantViolation("a room on record has no saver"))?;
        drop(state);
        Ok(Some(self.check_saver(saver)))
    }

    /// The [`Landing`] a base write on `route`, a route taken earlier, runs
    /// first in its transaction.
    pub(super) fn landing<'r>(
        &self,
        route: &'r SessionWriteRoute,
    ) -> Result<Landing<'r, '_, 'vault>> {
        Ok(Landing {
            route,
            session: self,
            saver: self.saver_check_for(route)?,
        })
    }

    fn check_saver(&self, saver: OnRecordSaver) -> SaverCheck<'_, 'vault> {
        SaverCheck {
            session: self,
            saver,
            lapsed: AtomicBool::new(false),
        }
    }

    /// The saver of this stretch's room while it is on record, read before
    /// a landing's write transaction (the state lock is never taken inside
    /// one).
    fn on_record_saver(&self) -> Result<Option<OnRecordSaver>> {
        let state = session_entry_state(&self.entry)?;
        Ok(match state.record.mode {
            OffRecordMode::OnRecord => state.saver.clone(),
            OffRecordMode::OffRecord | OffRecordMode::Anonymous => None,
        })
    }

    /// Stops the saving `saver` started: the stretch goes back off record
    /// for later turns, and the room hears that saving stopped. Saving that
    /// someone else started since is theirs, and goes on.
    fn stop_saving(&self, saver: &OnRecordSaver) -> Result<()> {
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
        let hearing = Hearing::now(self.vault, state.record.room);
        post_notice(
            &mut state,
            OffRecordNoticeAct::SavingStopped,
            saver.owner.actor(),
            hearing,
        );
        self.entry.publish_state(&state);
        Ok(())
    }

    /// Stops the saving when this stretch's room is on record and its saver
    /// no longer holds in a fresh snapshot.
    pub(super) fn lapse_saver(&self) -> Result<()> {
        let Some(saver) = self.on_record_saver()? else {
            return Ok(());
        };
        if saver.holds_in_txn(self.vault, &self.vault.store.env.read_txn()?)? {
            return Ok(());
        }
        self.stop_saving(&saver)
    }

    /// One write transaction for this stretch, in which `check` runs before
    /// `write`: a run's handle writes only while its participant is in the
    /// room, and a room on record writes into base only while its saver holds.
    pub(crate) fn with_saver_write_txn<T>(
        &self,
        check: Option<SaverCheck<'_, '_>>,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        self.vault.with_write_txn_grouped(|wtxn| {
            self.participant_and_saver_in_txn(check.as_ref(), wtxn)?;
            write(wtxn)
        })
    }

    /// A run's participant, then `saver`, in `txn`. A run removed from the
    /// room is refused as that and nothing else: it never hears the saver's
    /// state. The saver is still checked, so one found lapsed here still
    /// stops the saving once its check drops.
    fn participant_and_saver_in_txn(
        &self,
        saver: Option<&SaverCheck<'_, '_>>,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let admitted = self.participant_in_txn(txn);
        let held = saver.map_or(Ok(()), |saver| saver.in_txn(txn));
        admitted?;
        held
    }

    /// The refusal of a landing whose saver no longer holds: nothing of it
    /// was kept, and saving has stopped.
    fn saving_stopped(&self, saver: &OnRecordSaver) -> Error {
        Error::OffRecord(OffRecordError::OffRecordSavingStopped {
            session_ref: self.session_ref.clone(),
            saver_ref: saver.owner.actor().to_hex(),
        })
    }
}
