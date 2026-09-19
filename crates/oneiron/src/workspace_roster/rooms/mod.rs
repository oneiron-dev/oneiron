//! Room participation and addressed turn claims. Joining grants no memory scope.
#[cfg(test)]
mod tests;
mod witness;
use super::ProjectRoom;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(crate) use witness::admit_witness;

pub const ROOMS_VERBS: [&str; 4] = ["rooms.list", "rooms.messages", "rooms.speak", "rooms.claim"];
const TURNS: &[u8] = b"rooms.turn.v1/";
const HANDLES: &[u8] = b"rooms.platform_handle.v1/";
const CLAIMS: &[u8] = b"rooms.claim.v1/";
fn key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}
fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid())
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid room operation".into())
}
fn room_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<ProjectRoom> {
    super::project::record(
        &vault.store,
        txn,
        room,
        crate::registry::ENTITY_TYPE_CONVERSATION,
    )?
    .ok_or_else(invalid)
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
    let bytes = vault
        .store
        .vault_meta
        .get(txn, &key(TURNS, id))?
        .ok_or_else(invalid)?;
    decode(&bytes)
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
pub struct RoomClaimReceipt {
    pub room_id: String,
    pub turn_id: String,
    pub actor: String,
    pub receipt_ref: String,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
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
            let key = [HANDLES, room.as_bytes(), handle.as_bytes()].concat();
            self.store.vault_meta.put(txn, &key, actor.as_bytes())?;
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
            .prefix_iter(&txn, &[crate::registry::ENTITY_TYPE_CONVERSATION])
            .map_err(Error::from)?
        {
            let (key, _) = row.map_err(Error::from)?;
            let id = EntityId::from_bytes(key[1..].try_into().map_err(|_| invalid())?)?;
            if let Ok(room) = room_in(self.vault(), &txn, id)
                && room.member_ids.contains(&self.actor().to_hex())
            {
                result.push((id, room));
            }
        }
        Ok(result)
    }
    pub fn rooms_messages(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let mut rows: Vec<RoomTurn> = Vec::new();
        for row in self
            .vault()
            .store
            .vault_meta
            .prefix_iter(&txn, TURNS)
            .map_err(Error::from)?
        {
            let (_, bytes) = row.map_err(Error::from)?;
            let turn: RoomTurn = decode(&bytes)?;
            if turn.room_id == room.to_hex() {
                rows.push(turn);
            }
        }
        rows.sort_by(|a, b| (a.at, &a.turn_id).cmp(&(b.at, &b.turn_id)));
        Ok(rows)
    }
    /// Canonical HEAD is a read-time view. Branch turns never enter this path.
    pub fn room_head(&self, room: EntityId) -> MemoryResult<Option<RoomTurn>> {
        Ok(self
            .rooms_messages(room)?
            .into_iter()
            .rev()
            .find(|turn| turn.thread_of.is_none()))
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
            let key = key(CLAIMS, turn);
            if let Some(raw) = self.vault().store.vault_meta.get(txn, &key)? {
                let claim: RoomClaimReceipt = decode(&raw)?;
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
                receipt_ref: format!("rooms.claim:{}", EntityId::now().to_hex()),
                at: now,
            };
            self.vault()
                .store
                .vault_meta
                .put(txn, &key, &encode(&receipt)?)?;
            Ok(RoomClaimOutcome::Claimed(receipt))
        })
    }
    /// Uses the normal witness gate. The common witness transaction verifies
    /// the claim, membership, reply binding, and addressing before any message.
    pub fn rooms_speak(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        let room = EntityId::from_hex(&turn.conversation_ref)?;
        self.rooms_messages(room)?;
        self.witness(turn)
    }
}
