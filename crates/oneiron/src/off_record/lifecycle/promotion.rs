//! Promotion out of the room (ARCH-0052 D4): the one session-overlay-to-base
//! write, and the doors that save a turn, or a room's talk, through it.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::off_record::promote::{FloorWrites, PromoteInitiator, PromoteOutcome};

use super::registry::session_entry_state;
use super::room::{Hearing, post_notice};
use super::session::OffRecordSession;

impl OffRecordSession<'_> {
    /// Promotes exactly ONE witnessed turn out of the room and into the
    /// durable vault (ARCH-0052 D4, ONE-1730), for `owner`.
    ///
    /// This is the ONLY session-overlay-to-base write. It selects the turn's
    /// closure from the TYPED JOURNAL — never from overlay index keys, which
    /// are shared across turns — and replays that closure through the ordinary
    /// batch pipeline against current base state, so base indexes, canonical
    /// short ids, counters, validators, gates, and decision receipts are all
    /// re-derived exactly as for any other write.
    ///
    /// A promotion publishes what was said off record, so it is the owner's
    /// act, alone or in a room: `owner`'s proof is rechecked in the
    /// transaction that replays the turn, so a promotion queued behind a
    /// revocation writes nothing, and the turn's receipt names them.
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
    ///
    /// There is no promotion without the proof (H203):
    ///
    /// ```compile_fail
    /// fn promote(session: &oneiron::off_record::OffRecordSession<'_>, turn: &oneiron::EntityId) {
    ///     let _ = session.promote_turn(turn);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds.
    pub fn promote_turn_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        turn: &EntityId,
    ) -> Result<PromoteOutcome> {
        // In a room, the owner must be on its roster before anything is
        // answered (read before the state lock, which the roster read takes).
        if self.room()?.is_some() {
            let actor = owner
                .revalidate_as_vault_owner_in_txn(self.vault, &self.vault.store.env.read_txn()?)?;
            self.require_in_room(actor)?;
        }
        let outcome = {
            let mut state = self.recording_state()?;
            let room = state.record.room.map(EntityId::from_bytes).transpose()?;
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
                // The receipt answers only someone who could save the turn
                // now: their proof holds, they own this vault and, in a room,
                // their membership shows every moment of it. The room hears
                // this save as it heard the first; nothing more is kept.
                let txn = self.vault.store.env.read_txn()?;
                let actor = owner.revalidate_as_vault_owner_in_txn(self.vault, &txn)?;
                if let Some(room) = room {
                    let times = state.kept_times(*turn);
                    super::room::require_sight_in_txn(
                        self.vault,
                        &txn,
                        &self.session_ref,
                        room,
                        actor,
                        &times,
                    )?;
                    let hearing = Hearing::in_txn(self.vault, &txn, Some(room));
                    drop(txn);
                    post_notice(
                        &mut state,
                        super::types::OffRecordNoticeAct::SavedTurn,
                        actor,
                        hearing,
                    );
                    self.entry.publish_state(&state);
                }
                return Ok(receipt.outcome);
            }
            // The snapshot is taken under the state lock, so no close or other
            // save moves the journal under it. A witness can still publish into
            // the turn before the commit; retirement removes only the entries
            // this plan was cut from, so what it said stays in the room.
            let snapshot = self.entry.overlay.snapshot()?;
            // A save in a room keeps what the room showed of the turn.
            let plan = match room {
                Some(_) => super::saving::copy_plan(&snapshot, *turn)?.ok_or_else(|| {
                    Error::OffRecord(OffRecordError::OffRecordTurnNotInJournal {
                        turn_ref: turn.to_hex(),
                    })
                })?,
                None => snapshot.plan_promotion(*turn)?,
            };
            let times = super::saving::turn_times(&snapshot, *turn);
            drop(snapshot);
            // Who hears the save is read in the transaction that keeps it.
            let initiator = PromoteInitiator::owner(self.vault, owner)?;
            let (mut outcomes, (actor, hearing)) =
                self.promote_plans(&mut state, vec![plan], &initiator, |wtxn| {
                    // Alone or in a room, the turn lands in this vault, so
                    // the proof must show its owner.
                    let actor = owner.revalidate_as_vault_owner_in_txn(self.vault, wtxn)?;
                    if let Some(room) = room {
                        super::room::require_sight_in_txn(
                            self.vault,
                            wtxn,
                            &self.session_ref,
                            room,
                            actor,
                            &times,
                        )?;
                    }
                    Ok((actor, Hearing::in_txn(self.vault, wtxn, room)))
                })?;
            post_notice(
                &mut state,
                super::types::OffRecordNoticeAct::SavedTurn,
                actor,
                hearing,
            );
            self.entry.publish_state(&state);
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
    /// passes inside it, then publishes what base now holds as kept and
    /// retires exactly that from the room, and returns what `check` read
    /// there with the outcomes. A plan that [`appends`] to a turn this
    /// stretch saved goes through the floor's copy into a saved turn; any
    /// other through promote. The caller holds the state lock across
    /// selection and this commit (state -> base writer, the one lock order).
    ///
    /// Nothing observable happens until the commit returns. Only then does
    /// the record publish the turns as promoted and the overlay retire the
    /// committed closures. A crash between the two is safe: the durable
    /// receipts answer a retry, and a crashed process evaporates the overlay.
    ///
    /// What is kept and retired is what base holds by this stretch's saves,
    /// as the floor reports it, never merely what a plan asked for: a
    /// receipt that answers for a turn keeps only the closure it names, and
    /// an entry of the plan base does not hold stays in the room.
    ///
    /// A result MESSAGE a plan keeps lands with its hold on the body, read
    /// out of this room (FIX 365); a body the room spilled to a file is in
    /// the vault's `bodies/` before the transaction, pinned until it ends,
    /// and gone then unless a row of it names it (FIX 3633).
    ///
    /// [`appends`]: crate::session_overlay::PromotePlan::appends
    pub(super) fn promote_plans<T>(
        &self,
        state: &mut super::registry::OffRecordSessionEntryState,
        plans: Vec<crate::session_overlay::PromotePlan>,
        initiator: &PromoteInitiator,
        check: impl FnOnce(&heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<(Vec<(EntityId, PromoteOutcome)>, T)> {
        let floor = FloorWrites::new(&self.vault.store).saving(self.entry.overlay.clone());
        #[cfg(unix)]
        let bodies = floor.import_result_bodies(self.vault, &self.session_ref, &plans)?;
        let saved = self.vault.with_write_txn_grouped(|wtxn| {
            let checked = check(wtxn)?;
            let promoted_at = self.vault.store.clock.now_recorded_at();
            plans
                .iter()
                .map(|plan| {
                    if plan.appends() {
                        floor
                            .copy_append(
                                self.vault,
                                wtxn,
                                &self.session_ref,
                                plan,
                                initiator,
                                promoted_at,
                            )
                            .map(|appended| (appended.outcome, appended.held))
                    } else {
                        floor
                            .promote(
                                self.vault,
                                wtxn,
                                &self.session_ref,
                                plan,
                                initiator,
                                promoted_at,
                            )
                            .map(|outcome| {
                                let held: BTreeSet<EntityId> =
                                    outcome.replayed.iter().copied().collect();
                                (outcome, held)
                            })
                    }
                })
                .collect::<Result<Vec<_>>>()
                .map(|landed| (landed, checked))
        });
        // A copy no row of the save names, refused or skipped, leaves now.
        #[cfg(unix)]
        self.vault.discard_unnamed_promoted_bodies(bodies);
        let (landed, checked) = saved?;
        // Committed. Publish the RAM state, then drop the kept rows and
        // journal entries from the room — in that order, and never before.
        for (plan, (_, held)) in plans.iter().zip(&landed) {
            let turn = *plan.turn().as_bytes();
            if !state.record.promoted_turns.contains(&turn) {
                state.record.promoted_turns.push(turn);
            }
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
                    } if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE
                        && held.contains(id) =>
                    {
                        Some((*id, occurred.start, data.as_slice()))
                    }
                    _ => None,
                })
                .collect();
            state.keep_messages(plan.turn(), &messages);
        }
        self.entry.publish_state(state);
        for (plan, (_, held)) in plans.iter().zip(&landed) {
            // Best-effort for the same reason the window refresh is: the
            // subgraph and its receipt are already durable, so a failure to
            // tidy the ROOM must not tell the caller their consented promotion
            // did not happen. The un-retired rows are byte-identical to the
            // base rows the replay just wrote and evaporate at close.
            if let Err(error) = self.entry.overlay.retire_promoted_closure(plan, held) {
                tracing::warn!(
                    turn = %plan.turn().to_hex(),
                    error = %error,
                    "off-record promotion committed but overlay closure retirement deferred to close"
                );
            }
        }
        // A copy into a saved turn that found nothing new to copy saved
        // nothing, so it names no turn.
        let outcomes = plans
            .iter()
            .zip(landed)
            .filter(|(plan, (outcome, _))| !plan.appends() || !outcome.replayed.is_empty())
            .map(|(plan, (outcome, _))| (plan.turn(), outcome))
            .collect();
        Ok((outcomes, checked))
    }

    /// Refreshes the live sync windows for turns whose promotion committed.
    pub(super) fn refresh_promoted_turns(&self, turns: &[EntityId]) {
        #[cfg(feature = "sync")]
        for turn in turns {
            if let Err(error) = self.vault.refresh_promoted_turn_in_live_window(turn) {
                tracing::warn!(
                    turn = %turn.to_hex(),
                    kind = ?error.kind(),
                    "off-record promotion committed but live-window sync refresh deferred to recovery"
                );
            }
        }
        #[cfg(not(feature = "sync"))]
        let _ = turns;
    }
}
