//! That a room's private threads exist (owner ruling 2026-10-20, FIX 6381,
//! 6384; replaces FIX 6338): "The Owner and Admins can SEE that they exist
//! (id, creator, created date, last-active date, member count; never the
//! name, the member list or the words)".
//!
//! `vault.rooms.private_threads` lists each private thread of a room by
//! those five facts alone: its root's id, who opened it (no one once this
//! vault erased them), the root's own time, the time of its newest turn or
//! audience TURN, and how many are in its audience now. No title, member
//! id, turn byte, seed, anchor or snippet leaves it. The vault's Owner and
//! an Admin read it, seated in the room or not, whatever the thread's own
//! Scope reads; so does the companion agent of either, through its
//! companion PERSON to the live Owner or Admin it was onboarded for, read
//! again in the same snapshot. The list gives the companion these facts
//! alone: no walk-in, delete or read of a thread. Anyone else is refused as
//! an unknown room is. A credential narrowed by a world, facet, record or
//! channel caveat lists the threads of a room only its own read lane reads
//! the record of, in the list's snapshot, and of any other room nothing,
//! never a refusal (FIX 6500); one bounded by the whole vault, and a handle
//! bound to no credential, lists every room's. A credential's proof is read
//! again in the list's snapshot, a whole-vault one's too (FIX 6502), and so
//! is the slip of one whose lane does not build (FIX 6641): one
//! revoked or expired by then is refused as the scoped read refuses it,
//! naming that credential. The room's history is read whole, however long
//! (rule 5): no cap, no count refusal.

use super::audience::thread_binding;
use super::audience_doors::vault_owner_or_admin_in;
use super::audience_events::{erased_from_room_in, fold_audience_in};
use super::*;
use crate::authority::VerifiedSlip;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::federation::Scope;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_TURN};
use crate::scan_check::{EngineScan, ScanCount};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeMap;

/// `vault.rooms.private_threads`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPrivateThreadsRequest {
    /// The room, 32-hex.
    pub room_ref: String,
}

/// That one private thread of a room exists: these five facts, nothing
/// else of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadMetadata {
    /// The thread's root TURN, 32-hex.
    pub id: String,
    /// Who opened it, 32-hex; null once this vault erased them.
    pub creator: Option<String>,
    /// The root's own time, Unix seconds.
    pub created_at: u64,
    /// The time of its newest turn or audience TURN, Unix seconds.
    pub last_active_at: u64,
    /// How many are in its audience now.
    pub member_count: usize,
}

/// One private root as the room's history finds it.
struct FoundRoot {
    root: EntityId,
    seed: BTreeSet<EntityId>,
    created_at: u64,
}

impl Memory<'_> {
    /// `vault.rooms.private_threads`: each private thread of the room, by
    /// its five facts (module docs), in the room's history order, for the
    /// vault's Owner, an Admin or the companion agent of either. Anyone
    /// else, and a room that is unknown, meets the refusal an unknown room
    /// meets. A narrowed credential's list of a room its lane does not
    /// read is empty (FIX 6500).
    pub fn rooms_private_threads(
        &self,
        input: &RoomPrivateThreadsRequest,
    ) -> MemoryResult<Vec<PrivateThreadMetadata>> {
        let room = EntityId::from_hex(&input.room_ref)?;
        // A turn bound to one room lists no other room's threads.
        if self.room_turn().is_some_and(|turn| turn.room != room) {
            return Err(MemoryError::from(invalid()));
        }
        // A presented credential's lane, built before the list's snapshot
        // opens (one per thread), with whether it is bounded by the whole
        // vault. A narrowed one that does not build reaches no room.
        let presented = self.presented_credential().map(|proof| {
            (
                bounded_by_whole_vault(proof),
                self.read_lane(ClaimReadStatus::Recorded).ok(),
            )
        });
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        // Its proof, read again in this snapshot (FIX 6502); one whose lane
        // did not build has its slip read again itself (FIX 6641).
        let live = match (&presented, self.presented_credential()) {
            (Some((_, Some(lane))), _) => lane.proof_live_in(&txn)?,
            (Some((_, None)), Some(proof)) => vault.capability_slip_is_live_in_txn(&txn, proof)?,
            _ => true,
        };
        if !live {
            return Err(MemoryError::from(Error::InvalidClaimBody(
                "scoped read credential no longer live",
            )));
        }
        if !self.lists_private_threads_in(&txn)? {
            return Err(MemoryError::from(invalid()));
        }
        room_in(vault, &txn, room)?;
        if let Some((false, lane)) = &presented
            && !lane_reaches_room_in(lane.as_ref(), &txn, room)
        {
            return Ok(Vec::new());
        }
        let mut count = ScanCount::start(
            &vault.store,
            &txn,
            EngineScan::RoomHistoryRows,
            room.as_bytes(),
        )?;
        let mut roots = Vec::new();
        // Each thread's newest turn, by its root.
        let mut newest: BTreeMap<EntityId, u64> = BTreeMap::new();
        for row in HISTORY.iter_from(&vault.store, &txn, room.as_bytes())? {
            count.row();
            let ((_, at, _), turn) = row?;
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } = live_entity_row_in_txn(&vault.store, &txn, &turn)?
            else {
                continue;
            };
            let Some(binding) = thread_binding(&body)?.filter(|binding| binding.room == room)
            else {
                continue;
            };
            let slot = newest.entry(binding.root).or_insert(at);
            *slot = (*slot).max(at);
            if binding.root == turn
                && let Some(seed) = binding.audience
            {
                roots.push(FoundRoot {
                    root: turn,
                    seed,
                    created_at: at,
                });
            }
        }
        let mut listed = Vec::with_capacity(roots.len());
        for found in roots {
            let folded = fold_audience_in(vault, &txn, room, found.root, &found.seed)?;
            let mut last_active_at = newest.get(&found.root).copied().unwrap_or(found.created_at);
            // The thread's audience TURNs are its activity too.
            for edit in folded.turns() {
                if let Some(header) = vault.entity_header_in_txn(&txn, edit)? {
                    last_active_at = last_active_at.max(header.occurred_start);
                }
            }
            let creator = match TURNS.get(&vault.store, &txn, &found.root)? {
                Some(turn) => match EntityId::from_hex(&turn.actor) {
                    Ok(actor) if !erased_from_room_in(vault, &txn, room, actor)? => {
                        Some(actor.to_hex())
                    }
                    _ => None,
                },
                None => None,
            };
            listed.push(PrivateThreadMetadata {
                id: found.root.to_hex(),
                creator,
                created_at: found.created_at,
                last_active_at,
                member_count: folded.current().len(),
            });
        }
        drop(txn);
        count.finish(vault);
        Ok(listed)
    }

    /// Whether this actor reads a room's private-thread list in `txn`: the
    /// vault's Owner or an Admin, a pen through its PERSON, or the
    /// companion agent of either, whose companion PERSON was onboarded for
    /// a live Owner or Admin, read in this same snapshot (FIX 6384).
    fn lists_private_threads_in(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let vault = self.vault();
        let actor = self.actor();
        if vault_owner_or_admin_in(vault, txn, actor)? {
            return Ok(true);
        }
        if vault.get_entity_type_in_txn(txn, &actor)? != Some(ENTITY_TYPE_AGENT_DEF) {
            return Ok(false);
        }
        let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        let Some(companion) =
            crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
        else {
            return Ok(false);
        };
        match crate::workspace_roster::codec::companion_principal_in_txn(vault, txn, companion)? {
            Some(principal) if principal != companion => {
                vault_owner_or_admin_in(vault, txn, principal)
            }
            _ => Ok(false),
        }
    }
}

/// Whether `proof` bounds its records by the whole vault (FIX 6500): no
/// record or channel caveat, and every axis but its verbs at the top, as
/// `unrestricted_record_scope` admits it.
fn bounded_by_whole_vault(proof: &VerifiedSlip) -> bool {
    let mut required = Scope::top();
    required.verbs = proof.scope().verbs.clone();
    proof.claims().records.is_empty()
        && proof.claims().channels.is_empty()
        && required.is_narrowing_of(proof.scope())
}

/// Whether a narrowed credential's `lane` reads `room`'s record in `txn`
/// (FIX 6500). No lane, or a read that fails, logged, reaches no room: its
/// list is empty, never a refusal.
fn lane_reaches_room_in(
    lane: Option<&ScopedRead<'_>>,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> bool {
    let Some(lane) = lane else {
        return false;
    };
    match lane.entities_readable_in_txn(txn, &[room]) {
        Ok(read) => read.into_iter().all(|readable| readable),
        Err(error) => {
            tracing::warn!(
                room = %room.to_hex(),
                %error,
                "private thread list: the credential's reach of the room not read"
            );
            false
        }
    }
}
