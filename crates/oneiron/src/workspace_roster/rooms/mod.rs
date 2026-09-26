//! Room participation and addressed turn claims. Joining grants no memory scope.
mod history;
#[cfg(test)]
mod tests;
mod witness;
use super::ProjectRoom;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{EntityId, Vault};
pub(super) use history::delete_room_metadata;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(crate) use witness::admit_witness;

/// One addressed room turn (actor, addressed agents, message ids, reply/thread links). Key: id16
/// (turn id).
const TURNS: SideTable<EntityId, RoomTurn, LegacyJson> = SideTable::new(&side_table::ROOMS_TURN);
/// Maps a host-configured platform handle to the one present actor it addresses within a room.
/// Key: id16 (room id) + bytes (platform handle).
const HANDLES: SideTable<(EntityId, String), EntityId, Raw> =
    SideTable::new(&side_table::ROOMS_HANDLE);
/// Claim-before-speaking receipt naming which actor may respond to one addressed turn. Key: id16
/// (turn id).
const CLAIMS: SideTable<EntityId, RoomClaimReceipt, LegacyJson> =
    SideTable::new(&side_table::ROOMS_CLAIM);
/// Chronological index of every turn in a room, walked for paged message history. Key: id16
/// (room) + u64be (at) + id16 (turn).
const HISTORY: SideTable<(EntityId, u64, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::ROOMS_HISTORY);
/// Chronological index of non-branch (thread-root) turns, walked in reverse for the canonical
/// room head. Key: id16 (room) + u64be (at) + id16 (turn).
const HEADS: SideTable<(EntityId, u64, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::ROOMS_HEADS);
/// Single-response-per-claim guard: which turn already answered one claimed parent turn. Key:
/// id16 (parent turn id).
const RESPONSE: SideTable<EntityId, EntityId, Raw> = SideTable::new(&side_table::ROOMS_RESPONSE);

fn invalid() -> Error {
    Error::InvalidConfig("invalid room operation".into())
}
fn room_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<ProjectRoom> {
    let room: ProjectRoom = super::project::record(
        &vault.store,
        txn,
        room,
        crate::registry::ENTITY_TYPE_CONVERSATION,
    )?
    .ok_or_else(invalid)?;
    let project_id = EntityId::from_hex(&room.project_id)?;
    let project: super::ProjectRecord =
        super::project::record(&vault.store, txn, project_id, vault.project_type_byte()?)?
            .ok_or_else(invalid)?;
    if project.roster != room.member_ids || project.claims_scope_ref != room.claims_scope_ref {
        return Err(invalid());
    }
    Ok(room)
}
fn require_member(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<ProjectRoom> {
    let record = room_in(vault, txn, room)?;
    if !record.member_ids.contains(&actor.to_hex()) {
        return Err(invalid());
    }
    Ok(record)
}
fn turn_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<RoomTurn> {
    TURNS.get(&vault.store, txn, &id)?.ok_or_else(invalid)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomTurn {
    pub turn_id: String,
    pub room_id: String,
    pub actor: String,
    pub addressed_agents: BTreeSet<String>,
    pub message_ids: Vec<String>,
    pub reply_to: Option<String>,
    pub thread_of: Option<String>,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomPage {
    pub rows: Vec<RoomTurn>,
    pub next_after: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomClaimReceipt {
    pub room_id: String,
    pub turn_id: String,
    pub actor: String,
    pub receipt_ref: String,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomClaimOutcome {
    Claimed(RoomClaimReceipt),
    HeldBy(RoomClaimReceipt),
    NotAddressed,
}

impl Vault {
    /// Host roster configuration, not a user message. A platform handle maps
    /// to exactly one present actor. The mapping never creates grants.
    pub fn bind_room_handle(&self, room: EntityId, handle: &str, actor: EntityId) -> Result<()> {
        if handle.is_empty() || handle.len() > 256 || handle.contains('\0') {
            return Err(invalid());
        }
        self.with_write_txn(|txn| {
            require_member(self, txn, room, actor)?;
            HANDLES.put(&self.store, txn, &(room, handle.to_owned()), &actor)?;
            Ok(())
        })
    }
}
impl Memory<'_> {
    pub fn rooms_list(&self) -> MemoryResult<Vec<(EntityId, ProjectRoom)>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let mut result = Vec::new();
        for row in self
            .vault()
            .store
            .type_index
            .prefix_iter(&txn, &[crate::registry::ENTITY_TYPE_CONVERSATION])?
        {
            let (key, _) = row?;
            let id = EntityId::from_bytes(key[1..].try_into().map_err(|_| invalid())?)?;
            if let Ok(room) = room_in(self.vault(), &txn, id)
                && room.member_ids.contains(&self.actor().to_hex())
            {
                result.push((id, room));
            }
        }
        Ok(result)
    }
    pub fn rooms_claim(
        &self,
        room: EntityId,
        turn: EntityId,
        now: u64,
    ) -> MemoryResult<RoomClaimOutcome> {
        self.with_verified_actor_write_txn(|txn| {
            require_member(self.vault(), txn, room, self.actor())?;
            let addressed = turn_in(self.vault(), txn, turn)?;
            if addressed.room_id != room.to_hex() {
                return Err(MemoryError::from(invalid()));
            }
            if !addressed.addressed_agents.is_empty()
                && !addressed.addressed_agents.contains(&self.actor().to_hex())
            {
                return Ok(RoomClaimOutcome::NotAddressed);
            }
            if let Some(claim) = CLAIMS.get(&self.vault().store, txn, &turn)? {
                return Ok(if claim.actor == self.actor().to_hex() {
                    RoomClaimOutcome::Claimed(claim)
                } else {
                    RoomClaimOutcome::HeldBy(claim)
                });
            }
            let receipt = RoomClaimReceipt {
                room_id: room.to_hex(),
                turn_id: turn.to_hex(),
                actor: self.actor().to_hex(),
                receipt_ref: format!(
                    "rooms.claim:{}",
                    self.vault().store.clock.entity_id()?.to_hex()
                ),
                at: now,
            };
            CLAIMS.put(&self.vault().store, txn, &turn, &receipt)?;
            Ok(RoomClaimOutcome::Claimed(receipt))
        })
    }
    /// Uses the normal witness gate. The common witness transaction verifies
    /// the claim, membership, reply binding, and addressing before any message.
    pub fn rooms_speak(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        let room = EntityId::from_hex(&turn.conversation_ref)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        drop(txn);
        self.witness(turn)
    }
}
