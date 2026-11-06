//! Who holds the next turn in a room, as the board's ROOM section renders it
//! (FIX 15646; ARCH-0067 §8: "the claims, which name who holds the next
//! turn and which rules are in force"; claim state is live board material,
//! never a mark inside a turn). Read fresh from the claim-before-speaking
//! receipts (`ROOMS_CLAIM`) and the one-response guard (`ROOMS_RESPONSE`)
//! for the room's newest turns, under the reader's own room and turn read
//! checks. The claim and witness writes stay the authority: a rendered
//! holder lets no one speak.

use crate::error::Error;
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Result};

use super::participation::require_reader;
use super::{CLAIMS, HISTORY, RESPONSE, RoomTurn, project_room_of, turn_in, turns_readable};

/// How many of the room's newest turns the ROOM section reads for open
/// speaking claims.
pub const ROOM_SPEAKING_TURNS: usize = 16;

/// One open turn among the room's newest: claimed and not yet answered, or
/// addressed to the reader with no claim yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSpeakingClaim {
    /// The turn the next answer answers.
    pub turn: EntityId,
    /// The actor whose claim holds the answer; `None` while the turn
    /// addresses the reader and nobody has claimed it.
    pub holder: Option<EntityId>,
}

impl Memory<'_> {
    /// The open speaking claims on `room`'s newest [`ROOM_SPEAKING_TURNS`]
    /// turns, newest first: each unanswered turn someone claimed, and each
    /// unanswered, unclaimed turn that names the reader. A turn whose
    /// claim's holder was erased stays claimed and lists no row. Only turns
    /// the reader may read are listed. Empty for an ordinary Conversation,
    /// which keeps no claim-before-speaking receipts, and when the room's
    /// Scope reads no turns.
    ///
    /// # Errors
    ///
    /// A reader that does not belong to a project room, and storage faults.
    pub fn room_speaking_claims(&self, room: EntityId) -> MemoryResult<Vec<RoomSpeakingClaim>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        // An ordinary Conversation's membership ledger stays its reader
        // gate, already met by the section it renders in.
        if project_room_of(self.vault(), &txn, room)?.is_none() {
            return Ok(Vec::new());
        }
        require_reader(self.vault(), &txn, room, self.actor())?;
        drop(txn);
        let worlds = self.room_read_worlds(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        if !turns_readable(&worlds) {
            return Ok(Vec::new());
        }
        let store = &self.vault().store;
        let me = self.actor().to_hex();
        let mut open: Vec<(RoomTurn, Option<EntityId>)> = Vec::new();
        for row in HISTORY
            .iter_rev_from(store, &txn, room.as_bytes())?
            .take(ROOM_SPEAKING_TURNS)
        {
            let (_, turn_id) = row?;
            if RESPONSE.get(store, &txn, &turn_id)?.is_some() {
                continue;
            }
            let claim = CLAIMS.get(store, &txn, &turn_id)?;
            let turn = turn_in(self.vault(), &txn, turn_id)?;
            match claim {
                // A claim whose holder was erased still holds the turn
                // (replica.rs carries it as the erased identity): no row
                // names that holder, and the turn is not offered as open.
                Some(receipt) if receipt.actor == crate::receipt::ERASED_CALL_IDENTITY => {}
                Some(receipt) => {
                    let holder = EntityId::from_hex(&receipt.actor).map_err(Error::from)?;
                    open.push((turn, Some(holder)));
                }
                None if turn.addressed_agents.contains(&me) => open.push((turn, None)),
                None => {}
            }
        }
        drop(txn);
        let readable: std::collections::BTreeSet<String> = self
            .admitted_turns(open.iter().map(|(turn, _)| turn.clone()).collect())?
            .into_iter()
            .map(|turn| turn.turn_id)
            .collect();
        open.into_iter()
            .filter(|(turn, _)| readable.contains(&turn.turn_id))
            .map(|(turn, holder)| -> Result<RoomSpeakingClaim> {
                Ok(RoomSpeakingClaim {
                    turn: EntityId::from_hex(&turn.turn_id)?,
                    holder,
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(Into::into)
    }
}
