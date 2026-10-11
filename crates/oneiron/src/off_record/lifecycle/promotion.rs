//! Promotion out of the room (ARCH-0052 D4): the one session-overlay-to-base
//! write, and the doors that save a turn, or a room's talk, through it.

use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::off_record::promote::{FloorWrites, PromoteOutcome};

use super::registry::session_entry_state;
use super::room::{Hearing, post_notice};
use super::session::OffRecordSession;

impl OffRecordSession<'_> {
    /// Promotes exactly ONE witnessed turn out of the room and into the
    /// durable vault (ARCH-0052 D4, ONE-1730).
    ///
    /// This is the ONLY session-overlay-to-base write. It selects the turn's
    /// closure from the TYPED JOURNAL — never from overlay index keys, which
    /// are shared across turns — and replays that closure through the ordinary
    /// batch pipeline against current base state, so base indexes, canonical
    /// short ids, counters, validators, gates, and decision receipts are all
    /// re-derived exactly as for any other write.
    ///
    /// # Locking
    ///
    /// The per-session state lock is held across SELECTION and the durable
    /// commit, so close cannot stamp `closing` and freeze a stale view in the
    /// middle of a promotion. The lock order is state -> base writer; nothing
    /// inside the write transaction takes the session state lock, so the order
    /// cannot invert.
    ///
    /// # Ordering after commit
    ///
    /// Nothing observable happens until `wtxn.commit()` returns. Only then does
    /// the session record publish the turn as promoted and the overlay retire
    /// the committed closure. A crash between the two is safe: the durable
    /// receipt answers the retry, and a crashed process evaporates the stale
    /// overlay outright.
    pub fn promote_turn(&self, turn: &EntityId) -> Result<PromoteOutcome> {
        self.promote_turn_bound(turn, None)
    }

    /// [`Self::promote_turn`] for a transport: `owner`'s proof is rechecked in
    /// the transaction that replays the turn, so a promotion queued behind a
    /// revocation writes nothing.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds; otherwise as [`Self::promote_turn`].
    pub fn promote_turn_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        turn: &EntityId,
    ) -> Result<PromoteOutcome> {
        self.promote_turn_bound(turn, Some(owner))
    }

    fn promote_turn_bound(
        &self,
        turn: &EntityId,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<PromoteOutcome> {
        // In a room, the owner must be on its roster before anything is
        // answered (read before the state lock, which the roster read takes).
        if let Some(owner) = owner
            && self.room()?.is_some()
        {
            self.require_in_room(owner.actor())?;
        }
        let outcome = {
            let mut state = self.recording_state()?;
            // A stretch in a room is saved only by someone with a proof, who
            // is in the room and could see the turn.
            let room = state.record.room.map(EntityId::from_bytes).transpose()?;
            if room.is_some() && owner.is_none() {
                return Err(super::room::unbound_in_room(&self.session_ref));
            }
            // RETRY, ahead of the journal: a promoted turn's closure has
            // already been retired from the overlay, so planning it again would
            // fail with "no journaled turn" for a turn that IS promoted. The
            // durable receipt is the answer, and it stays the answer after
            // close. `FloorWrites::promote` re-reads it inside the write
            // transaction, which is where the atomicity of that decision lives;
            // this read only spares the caller a plan it cannot build. In a
            // room only this stretch's own saved turns answer, so another
            // room's receipt reads as a turn this stretch never had.
            if (room.is_none() || state.record.promoted_turns.contains(turn.as_bytes()))
                && let Some(receipt) = self.vault.off_record_promote_receipt(turn)?
            {
                // In a room the receipt answers only someone who could save
                // the turn now: their proof holds, they own this vault, and
                // their membership shows every moment of it. The room hears
                // this save as it heard the first; nothing more is kept.
                if let (Some(room), Some(owner)) = (room, owner) {
                    let times = state.kept_times(*turn);
                    let txn = self.vault.store.env.read_txn()?;
                    owner.revalidate_as_vault_owner_in_txn(self.vault, &txn)?;
                    super::room::require_sight_in_txn(
                        self.vault,
                        &txn,
                        &self.session_ref,
                        room,
                        owner.actor(),
                        &times,
                    )?;
                    let hearing = Hearing::in_txn(self.vault, &txn, Some(room));
                    drop(txn);
                    post_notice(
                        &mut state,
                        super::types::OffRecordNoticeAct::SavedTurn,
                        owner.actor(),
                        hearing,
                    );
                    self.entry.publish_state(&state);
                }
                return Ok(receipt.outcome);
            }
            // The snapshot is taken under the state lock, so the journal this
            // plan is cut from is the journal the commit below applies against.
            let snapshot = self.entry.overlay.snapshot()?;
            // A save in a room keeps what the room showed of the turn.
            let plan = match room {
                Some(_) => super::room::copy_plan(&snapshot, *turn)?.ok_or_else(|| {
                    Error::OffRecord(OffRecordError::OffRecordTurnNotInJournal {
                        turn_ref: turn.to_hex(),
                    })
                })?,
                None => snapshot.plan_promotion(*turn)?,
            };
            let times = super::room::turn_times(&snapshot, *turn);
            drop(snapshot);
            // Who hears the save is read in the transaction that keeps it.
            let (mut outcomes, hearing) = self.promote_plans(&mut state, vec![plan], |wtxn| {
                let Some(owner) = owner else {
                    return Ok(None);
                };
                if room.is_some() {
                    owner.revalidate_as_vault_owner_in_txn(self.vault, wtxn)?;
                } else {
                    owner.revalidate_in_txn(self.vault, wtxn)?;
                }
                if let Some(room) = room {
                    super::room::require_sight_in_txn(
                        self.vault,
                        wtxn,
                        &self.session_ref,
                        room,
                        owner.actor(),
                        &times,
                    )?;
                }
                Ok(Some(Hearing::in_txn(self.vault, wtxn, room)))
            })?;
            if let (Some(owner), Some(hearing)) = (owner, hearing) {
                post_notice(
                    &mut state,
                    super::types::OffRecordNoticeAct::SavedTurn,
                    owner.actor(),
                    hearing,
                );
                self.entry.publish_state(&state);
            }
            outcomes
                .pop()
                .map(|(_, outcome)| outcome)
                .ok_or(Error::InvariantViolation(
                    "a promote of one turn returned none",
                ))?
        };

        // The promotion is durable here. The live-window refresh is best-effort
        // by contract: turning post-commit drift into an error would report a
        // failed promote for content that is committed and kept.
        self.refresh_promoted_turns(&[*turn]);
        Ok(outcome)
    }

    /// The session state, refused when the room is closing or keeps nothing.
    pub(super) fn recording_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, super::registry::OffRecordSessionEntryState>> {
        let state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        state
            .record
            .mode
            .write_target()
            .require_recording(&self.session_ref)?;
        Ok(state)
    }

    /// Replays `plans` into base in ONE write transaction, after `check`
    /// passes inside it, then publishes them as promoted and retires them
    /// from the room, and returns what `check` read there with the outcomes.
    /// The caller holds the state lock across selection and this commit
    /// (state -> base writer, the one lock order).
    ///
    /// Nothing observable happens until the commit returns. Only then does
    /// the record publish the turns as promoted and the overlay retire the
    /// committed closures. A crash between the two is safe: the durable
    /// receipts answer a retry, and a crashed process evaporates the overlay.
    pub(super) fn promote_plans<T>(
        &self,
        state: &mut super::registry::OffRecordSessionEntryState,
        plans: Vec<crate::session_overlay::PromotePlan>,
        check: impl FnOnce(&heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<(Vec<(EntityId, PromoteOutcome)>, T)> {
        let (outcomes, checked) = self.vault.with_write_txn_grouped(|wtxn| {
            let checked = check(wtxn)?;
            let floor = FloorWrites::new(&self.vault.store);
            let promoted_at = self.vault.store.clock.now_recorded_at();
            plans
                .iter()
                .map(|plan| {
                    floor
                        .promote(self.vault, wtxn, &self.session_ref, plan, promoted_at)
                        .map(|outcome| (plan.turn(), outcome))
                })
                .collect::<Result<Vec<_>>>()
                .map(|outcomes| (outcomes, checked))
        })?;
        // Committed. Publish the RAM state, then drop the promoted rows and
        // journal entries from the room — in that order, and never before.
        for plan in &plans {
            state.record.promoted_turns.push(*plan.turn().as_bytes());
            let messages: Vec<(EntityId, u64, &[u8])> = plan
                .ops
                .iter()
                .filter_map(|op| match op {
                    crate::batch::BatchOp::Put {
                        id,
                        entity_type,
                        occurred,
                        data,
                        ..
                    } if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE => {
                        Some((*id, occurred.start, data.as_slice()))
                    }
                    _ => None,
                })
                .collect();
            state.keep_messages(plan.turn(), &messages);
        }
        self.entry.publish_state(state);
        for plan in &plans {
            // Best-effort for the same reason the window refresh is: the
            // subgraph and its receipt are already durable, so a failure to
            // tidy the ROOM must not tell the caller their consented promotion
            // did not happen. The un-retired rows are byte-identical to the
            // base rows the replay just wrote and evaporate at close.
            if let Err(error) = self.entry.overlay.retire_promoted_closure(plan) {
                tracing::warn!(
                    turn = %plan.turn().to_hex(),
                    error = %error,
                    "off-record promotion committed but overlay closure retirement deferred to close"
                );
            }
        }
        Ok((outcomes, checked))
    }

    /// Refreshes the live sync windows for turns whose promotion committed.
    pub(super) fn refresh_promoted_turns(&self, turns: &[EntityId]) {
        #[cfg(feature = "sync")]
        for turn in turns {
            if let Err(error) = self.vault.refresh_promoted_turn_in_live_window(turn) {
                tracing::warn!(
                    turn = %turn.to_hex(),
                    error = %error,
                    "off-record promotion committed but live-window sync refresh deferred to recovery"
                );
            }
        }
        #[cfg(not(feature = "sync"))]
        let _ = turns;
    }
}
