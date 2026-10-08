//! Room participation and addressed turn claims. Joining grants no memory scope.
mod history;
mod liveness;
#[cfg(test)]
mod tests;
mod witness;
use super::ProjectRoom;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
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

/// One addressed room turn (actor, addressed agents, message ids, reply/thread links). Key: id16
/// (turn id).
pub(super) const TURNS: SideTable<EntityId, RoomTurn, LegacyJson> =
    SideTable::new(&side_table::ROOMS_TURN);
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
/// Parent-to-child index of a room's thread replies. Key: id16 (room) + id16 (parent turn) + id16
/// (child turn).
pub(super) const THREAD_CHILDREN: SideTable<(EntityId, EntityId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::ROOMS_THREAD_CHILDREN);

fn invalid() -> Error {
    Error::InvalidConfig("invalid room operation".into())
}
pub(super) fn room_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<ProjectRoom> {
    let room: ProjectRoom = super::project::record(
        &vault.store,
        txn,
        room,
        crate::registry::ENTITY_TYPE_CONVERSATION,
    )?
    .ok_or_else(invalid)?;
    let project_id = EntityId::from_hex(&room.project_id)?;
    let project = vault
        .visible_project_in_txn(txn, project_id)?
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
    #[serde(default)]
    pub task_ids: Vec<String>,
    #[serde(default)]
    pub converted_project: Option<String>,
}
/// The first trunk entry is the origin card when this room came from a thread.
/// It points to that thread without copying any of its messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomTrunkItem {
    Origin(super::project::RoomOriginCard),
    Turn(RoomTurn),
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
    /// The room Scope this page was read inside (ARCH-0067 §8).
    pub scope: crate::federation::Scope,
}

/// A room TURN is an ordinary record, not a claim, so it lives in base
/// reality: a room Scope without base reads none of the room's turns.
fn turns_readable(scope: &crate::federation::Scope) -> bool {
    scope
        .worlds
        .contains(&crate::federation::ScopeId(crate::claim::base_world_id()))
}

/// The refusal for a turn the room Scope cannot read.
fn outside_scope() -> MemoryError {
    MemoryError::bad_request_with("room turn is outside the room scope", &[])
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
        && !super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)?
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &room)?
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
            || super::project::ROOM_PROJECT
                .get(&self.store, &txn, &room)?
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
            HANDLES.put(&self.store, txn, &(room, handle.to_owned()), &actor)?;
            Ok(())
        })
    }
}
impl Memory<'_> {
    /// The caller's rooms. Inside a room turn, only that room, and only when
    /// its Scope reads base reality, where room records live.
    pub fn rooms_list(&self) -> MemoryResult<Vec<(EntityId, ProjectRoom)>> {
        let bound = match self.room_turn() {
            Some(turn) => Some((turn.room, self.room_read_scope(turn.room)?)),
            None => None,
        };
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        if let Some((room, scope)) = bound {
            if !turns_readable(&scope) {
                return Ok(Vec::new());
            }
            return Ok(vec![(
                room,
                require_member(self.vault(), &txn, room, self.actor())?,
            )]);
        }
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
        if !turns_readable(&self.room_read_scope(room)?) {
            return Err(outside_scope());
        }
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
        if !turns_readable(&self.room_read_scope(room)?) {
            return Err(outside_scope());
        }
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        drop(txn);
        self.witness(turn)
    }
}
