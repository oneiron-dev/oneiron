//! A room turn's ceiling as each row's snapshot refreshes it, and the
//! peer reads a room or audience conjoins (ARCH-0067 §8).

use super::*;

impl ScopedRead<'_> {
    /// Whether each of `peers` reads the revision `raw` too, under this
    /// read's claim-status contract; each as a personal ceiling's peer
    /// (`room_peer`) when `room_peer`.
    pub(super) fn peers_read_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        peers: &[ScopedReadActorKey],
        id: &EntityId,
        raw: &[u8],
        room_peer: bool,
    ) -> Result<bool> {
        for peer in peers {
            let mut peer = self
                .vault
                .scoped_read(peer.clone())
                .with_claim_status(self.claim_status);
            peer.room_peer = room_peer;
            // A member read as the owner must still be the owner in this
            // snapshot; one whose standing lapsed keeps the row out.
            match peer.owner_live_in(txn) {
                Ok(()) => {}
                Err(Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(_))) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            let policy = peer.policy_manifest_in(txn)?;
            let filter = crate::gate::narrow_retrieval_filter(
                &policy.retrieval_floor_for_actor(Some(&peer.actor_key)),
                None,
            )?;
            if !peer.is_entity_raw_readable_with_filter_in(txn, &policy, id, raw, &filter)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The ceiling `turn` puts on a row `txn` serves; `None` once the caller
    /// is off the room's roster here. The roster is read in this snapshot,
    /// and with it the room's live speakers (FIX 1388/1389), whose incomplete
    /// call holds the read before any held ceiling serves it. While everyone
    /// on the roster and every live entry already binds the ceiling this read
    /// holds, only clearances can have narrowed, so this snapshot's clearance
    /// meets into the turn. A member or entry it does not bind yet rebuilds
    /// the room from this snapshot and conjoins it. Either way a refresh
    /// narrows the turn, for this read and every later one, and never widens
    /// it. A thread's ceiling (`turn.branch`) re-proves standing on that
    /// thread instead, which its Ready receipt gives an agent off the room
    /// (OF-529), and takes no live entry. A refresh keeps the ceiling
    /// personal or held as `turn` is ([`RoomTurnCeiling::narrowed_by`]).
    pub(super) fn room_ceiling_in(
        &self,
        txn: &heed::RoTxn<'_>,
        turn: &RoomTurnCeiling,
    ) -> Result<Option<Arc<RoomTurnCeiling>>> {
        let Some(roster) = crate::context_board::room_roster_in(self.vault, txn, turn.room)? else {
            return Ok(None);
        };
        let reads = match turn.branch {
            Some(thread) => crate::context_board::thread_reader_in(
                self.vault,
                txn,
                turn.room,
                thread,
                &roster,
                turn.caller,
            )?,
            None => crate::context_board::room_reader_in(
                self.vault,
                txn,
                turn.room,
                &roster,
                turn.caller,
            )?,
        };
        if !reads {
            return Ok(None);
        }
        // A private thread's ceiling binds its audience alone (FIX 2951).
        let roster = match turn.branch {
            Some(thread) => crate::workspace_roster::thread_members_in(
                self.vault, txn, turn.room, thread, &roster,
            )?,
            None => roster,
        };
        let live = match turn.branch {
            Some(_) => None,
            None => Some(self.vault.room_live_speaker_entries_in(txn, turn.room)?),
        };
        let mut held = self
            .room_ceiling
            .lock()
            .map_err(|_| Error::InvariantViolation("room ceiling lock"))?;
        let current = held.get_or_insert_with(|| Arc::new(turn.clone()));
        if current.binds_all(&roster)
            && live
                .as_ref()
                .is_none_or(|live| current.binds_all(live.entry_refs()))
        {
            if current.terms.p7() {
                // The members' clearance alone: an entry ref is no member.
                let clearance = crate::context_board::room_clearance_in(self.vault, txn, &roster)?;
                current.terms.meet_clearance(clearance.as_ref());
                if let Some(live) = &live {
                    let unknown = self.vault.live_speaker_clearance_in(txn, live)?;
                    current.terms.meet_clearance(unknown.as_ref());
                }
            }
            return Ok(Some(Arc::clone(current)));
        }
        let now = match turn.branch {
            Some(thread) => crate::context_board::thread_ceiling_in(
                self.vault,
                txn,
                turn.room,
                thread,
                turn.caller,
            )?,
            None => crate::context_board::room_ceiling_in(self.vault, txn, turn.room, turn.caller)?,
        };
        let Some(now) = now else {
            return Ok(None);
        };
        self.room_ceilings_built
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *current = Arc::new(current.narrowed_by(&now));
        Ok(Some(Arc::clone(current)))
    }
}
