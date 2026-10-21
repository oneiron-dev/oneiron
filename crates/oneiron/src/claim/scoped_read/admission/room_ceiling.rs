//! A room turn's ceiling as each row's snapshot refreshes it, and the
//! peer reads a room or audience conjoins (ARCH-0067 §8).

use super::super::access_gate::HeldAuthority;
use super::*;

impl<'v> ScopedRead<'v> {
    /// Whether each of `peers` reads the revision `raw` too, under this
    /// read's claim-status contract; each as a personal ceiling's peer
    /// (`room_peer`) when `room_peer`. Each peer's own row admission is its
    /// own B, else its own A under its own live Grants (FIX 7462), held for
    /// this serving txn beside `authority`'s and never another's.
    pub(super) fn peers_read_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        peers: &[ScopedReadActorKey],
        id: &EntityId,
        raw: &[u8],
        room_peer: bool,
        authority: &HeldAuthority<'v>,
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
            let held = authority.for_peer();
            if !peer.is_entity_raw_readable_held_in(txn, &policy, id, raw, &filter, &held)? {
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
    /// (OF-529), and takes no live entry; an Owner or Admin reading a private
    /// thread off the room meets its own clearance beside its members'
    /// (FIX 6497), as the rebuild does. A refresh keeps the ceiling
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
        let mut roster = match turn.branch {
            Some(thread) => crate::workspace_roster::thread_members_in(
                self.vault, txn, turn.room, thread, &roster,
            )?,
            None => roster,
        };
        // One whose audience holds no member now, read by the vault's Owner
        // or an Admin in it off the room (FIX 6267), binds as
        // `thread_ceiling_in` binds it, so that caller's clearance meets into
        // the turn on each row as a member's does (FIX 6336).
        if let Some(thread) = turn.branch
            && roster.is_empty()
            && crate::workspace_roster::privileged_private_thread_reader_in(
                self.vault,
                txn,
                turn.room,
                thread,
                turn.caller,
            )?
        {
            roster = empty_private_thread_refresh_parties(turn.caller);
        }
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
                // The vault's Owner or an Admin reading a private thread off
                // the room beside its members meets its own too (FIX 6497).
                if let Some(thread) = turn.branch {
                    let own = crate::context_board::off_room_reader_clearance_in(
                        self.vault,
                        txn,
                        turn.room,
                        thread,
                        &roster,
                        turn.caller,
                    )?;
                    current.terms.meet_clearance(own.as_ref());
                }
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

/// Who a private thread's refreshed ceiling binds when its audience holds no
/// member now and `caller`, the vault's Owner or an Admin in it, reads it off
/// the room (FIX 6336; CALLS `FIX 6336 empty private thread refresh`,
/// EMPTY_PRIVATE_THREAD_REFRESH_PARTIES = CallerOnly): that caller alone,
/// never the room's members or every name in the audience. The vault owner
/// and the vault's own agents bring no clearance, so their reads stay open.
fn empty_private_thread_refresh_parties(caller: EntityId) -> Vec<EntityId> {
    vec![caller]
}
