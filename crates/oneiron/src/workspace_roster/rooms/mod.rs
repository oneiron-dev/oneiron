//! Room participation and addressed turn claims. Joining grants no memory scope.
mod history;
mod liveness;
#[cfg(test)]
mod tests;
mod witness;
use super::ProjectRoom;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn};
#[cfg(test)]
use crate::workspace_roster::RoomThreadFill;
use crate::{EntityId, Vault};
pub(super) use history::delete_room_metadata;
pub(crate) use liveness::RoomThreadTask;
pub use liveness::{
    RoomThread, RoomThreadList, RoomThreadPolicy, RoomThreadWait, RoomThreads, RoomWaitKind,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(crate) use witness::admit_witness;

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
pub(in crate::workspace_roster) fn require_member(
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
pub(in crate::workspace_roster) fn turn_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<RoomTurn> {
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
/// A delivered TASK's durable result, attached to its trunk on a room read.
/// The TASK terminal register holds the fact; no second row is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomTrunkHeader {
    pub thread: EntityId,
    pub task: EntityId,
    pub result_ref: EntityId,
}

/// A trunk turn with the delivered task headers under its thread anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomTrunk {
    pub turn: RoomTurn,
    pub headers: Vec<RoomTrunkHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomThreadPage {
    pub rows: Vec<EntityId>,
    /// Explicit end marker: `None` means the room has no further page.
    pub next_after: Option<EntityId>,
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

/// Project rooms use the PROJECT roster instead of the ordinary membership
/// ledger. Return None for other conversations so their historical membership
/// windows remain authoritative at the ordinary audience door.
pub(crate) fn project_room_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    audience: &[EntityId],
) -> Result<Option<bool>> {
    let Some(raw) = vault.store.entities.get(txn, room.as_bytes())? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
        return Ok(None);
    }
    let body = crate::conversation::ConversationBody::from_bytes(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    if !body.extra.contains_key("project_id")
        && !body.extra.contains_key("memberIds")
        && vault
            .store
            .vault_meta
            .get(
                txn,
                &[super::project::ROOM_PROJECT, room.as_bytes()].concat(),
            )?
            .is_none()
    {
        return Ok(None);
    }
    let room = room_in(vault, txn, room)?;
    Ok(Some(
        audience
            .iter()
            .all(|actor| room.member_ids.contains(&actor.to_hex())),
    ))
}

impl Vault {
    /// Resolve the audience of a room from its owning substrate. Project home
    /// rooms derive membership from the PROJECT roster, not from the ordinary
    /// Conversation membership ledger. Validate that reciprocal projection
    /// before using it; other Conversations keep their ledger-based audience.
    pub fn room_audience_members(&self, room: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        // A PROJECT and its exact room may arrive in the same batch. The
        // projector's equality path can then leave no marker behind; the
        // stored body, not that auxiliary row, identifies the substrate.
        let raw = self
            .store
            .entities
            .get(&txn, room.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
            return Err(invalid());
        }
        let body = crate::conversation::ConversationBody::from_bytes(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?;
        let derived = body.extra.contains_key("project_id") || body.extra.contains_key("memberIds");
        if derived
            || self
                .store
                .vault_meta
                .get(
                    &txn,
                    &[super::project::ROOM_PROJECT, room.as_bytes()].concat(),
                )?
                .is_some()
        {
            return room_in(self, &txn, room)?
                .member_ids
                .iter()
                .map(|id| EntityId::from_hex(id))
                .collect();
        }
        drop(txn);
        self.members(room)
    }

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
                receipt_ref: format!(
                    "rooms.claim:{}",
                    self.vault().store.clock.entity_id()?.to_hex()
                ),
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
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        drop(txn);
        self.witness(turn)
    }
}
