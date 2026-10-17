//! Room participation and addressed turn claims. Joining grants no memory scope.
mod audience;
mod history;
mod hosting;
mod liveness;
mod offer_activity;
mod offer_liveness;
mod offer_reopen;
mod offer_settle;
mod offers;
mod participants;
mod participation;
mod replica;
#[cfg(test)]
mod tests;
mod thread_projection;
mod upkeep;
mod witness;
use super::ProjectRoom;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessReceipt, WitnessTurn};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
#[cfg(test)]
use crate::workspace_roster::RoomThreadFill;
use crate::{EntityId, Vault};
pub(crate) use audience::{
    ROOM_THREAD_KEY, ThreadBinding, ThreadPlace, record_thread_admits_in,
    require_thread_audience_in, stamp_thread, thread_audience_allows_in, thread_audience_in,
    thread_binding, thread_members_in, thread_root_readable_in, validate_private_audience_in,
};
pub(super) use history::PAGE_LIMIT;
pub(super) use history::delete_room_metadata;
pub(crate) use history::erase_room_side_rows;
pub(in crate::workspace_roster) use history::index_task_bindings;
pub(crate) use history::task_binding_turns_in;
pub(in crate::workspace_roster) use history::thread_turns_in;
pub(in crate::workspace_roster) use hosting::room_host_in;
pub(crate) use hosting::room_project_in;
pub use hosting::{
    HostPin, HostPinKind, RoomHostHand, RoomHostPin, RoomHosting, RoomSpeakingRole, RoomStanding,
};
pub(crate) use liveness::RoomThreadTask;
pub use liveness::{
    RoomThread, RoomThreadList, RoomThreadPolicy, RoomThreadWait, RoomThreads, RoomWaitKind,
};
pub(in crate::workspace_roster) use liveness::{
    is_thread_root, thread_root_map, thread_task_bindings,
};
pub use offer_activity::OfferVoteRequest;
pub(crate) use offer_activity::{ROOM_OFFER_IDLE_SECS, record_offer_append_in_txn};
pub use offer_reopen::OfferReopenRequest;
pub use offer_settle::{OfferAnswer, OfferAnswerRequest, OfferSettlement};
pub use offers::{OfferCard, OfferDraft, OfferState, OfferVoteTally, OffersPage, OffersRequest};
pub use participants::{ParticipantView, ParticipantsPage, ParticipantsRequest};
pub use participation::JoinCause;
pub(super) use participation::record_bound_task_in_txn;
pub(crate) use participation::{
    Admitted, admit_participation_in_txn, join_subject_for_actor_in_txn,
};
use participation::{Claimant, agent_off_room_in_txn, require_reader, require_thread_reader};
pub(crate) use replica::{
    RoomSideRow, SideMerge, TurnMerge, clear_replicated_side_cell_in_txn,
    merge_replicated_responses_in_txn, merge_replicated_shared_row_in_txn,
    merge_replicated_side_row_in_txn, merge_replicated_turn_in_txn, merged_shared_row,
    replicated_shared_rows_in, replicated_side_carriers_in, replicated_side_rows_in,
    replicated_turn_in,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(crate) use thread_projection::room_thread_turns_in_txn;
pub use upkeep::{RoomUpkeepInput, RoomUpkeepThread, room_upkeep_input};
pub(crate) use upkeep::{room_upkeep_host, upkeep_rooms};
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
/// The room as its project's signed history vouches for it: the stored room
/// must match the stored project, and its members and claims scope are the
/// project's effective seats and scope (decision 7).
pub(super) fn room_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<ProjectRoom> {
    let mut room: ProjectRoom = super::project::record(
        &vault.store,
        txn,
        room,
        crate::registry::ENTITY_TYPE_CONVERSATION,
    )?
    .ok_or_else(invalid)?;
    let project_id = EntityId::from_hex(&room.project_id)?;
    let (project, effective) = vault
        .effective_project_in_txn(txn, project_id)?
        .ok_or_else(invalid)?;
    if project.roster != room.member_ids || project.claims_scope_ref != room.claims_scope_ref {
        return Err(invalid());
    }
    room.member_ids = effective.seat_list(project.members());
    room.claims_scope_ref = effective.claims_scope_ref;
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
    /// Its messages' quotes (OF-460, FIX 2028), on trunk and thread turns
    /// alike, keyed by the citing MESSAGE's id, one of `message_ids`. An
    /// entry is its message's birth fact: written once, in the message's own
    /// witness, and never changed; a later message adds its own.
    #[serde(default)]
    pub quotes: std::collections::BTreeMap<String, crate::conversation_dag::RoomQuote>,
}
/// The first trunk entry is the origin card when this room came from a thread.
/// It points to that thread without copying any of its messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomTrunkItem {
    Origin(super::project::RoomOriginCard),
    Turn(RoomTurn),
    Result(RoomTrunkHeader),
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
/// reality: a room whose world ceiling lacks base reads none of its turns.
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
/// windows remain authoritative at the ordinary audience door. Each audience
/// actor stands as [`participation::reads_room_in_txn`] reads the room: its
/// seat, or a live Ready receipt for the room (OF-417). A thread's receipt
/// opens no room-wide read.
pub(crate) fn project_room_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    audience: &[EntityId],
) -> Result<Option<bool>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(&vault.store, txn, &room)?
    else {
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
    let record = room_in(vault, txn, room)?;
    let at = vault.store.clock.now_recorded_at();
    for actor in audience {
        let subject = participation::participant_in_txn(vault, txn, *actor, at)?;
        if !participation::reads_room_in_txn(vault, txn, room, &record, *actor, subject)? {
            return Ok(Some(false));
        }
    }
    Ok(Some(true))
}

/// Whether `actor` stands in the ordinary room `room`'s audience on a live
/// Ready receipt for the room (OF-417): a home-room join, or a companion's
/// filed through its principal. The receipt is current read standing, re-proved
/// live, and grants no claim; a thread's receipt never satisfies it. Seats and
/// membership windows are the caller's own, so their history keeps its meaning.
pub(crate) fn room_join_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let at = vault.store.clock.now_recorded_at();
    let Some(subject) = participation::participant_in_txn(vault, txn, actor, at)? else {
        return Ok(false);
    };
    let receipt =
        participation::require_join_covering_in_txn(vault, txn, room, None, &subject, None);
    Ok(participation::joined(receipt)?.is_some())
}

/// The validated project room `room` is, or `None` for an ordinary
/// Conversation, whose membership ledger stays authoritative.
fn project_room_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<ProjectRoom>> {
    // A PROJECT and its exact room may arrive in the same batch. The
    // projector's equality path can then leave no marker behind; the
    // stored body, not that auxiliary row, identifies the substrate.
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)?
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
            .get(&vault.store, txn, &room)?
            .is_some()
    {
        return room_in(vault, txn, room).map(Some);
    }
    Ok(None)
}

impl Vault {
    /// Resolve the audience of a room from its owning substrate. Project home
    /// rooms derive membership from the PROJECT roster, not from the ordinary
    /// Conversation membership ledger. Validate that reciprocal projection
    /// before using it; other Conversations keep their ledger-based audience.
    pub fn room_audience_members(&self, room: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.room_audience_members_in_txn(&txn, room)
    }

    /// [`Self::room_audience_members`] as `read` reads the room, in one
    /// snapshot: a room `read` cannot read is a missing room, unless
    /// `member` is one of its members, who reads its roster by membership as
    /// its room turns do. Membership never widens the credential: one
    /// narrowed on any read axis or whose records leave the room out, or a
    /// caller whose locality keeps it here, reads it as missing.
    pub fn room_audience_members_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        room: EntityId,
        member: Option<EntityId>,
    ) -> Result<Vec<EntityId>> {
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&txn)?;
        if read.is_ref_readable_with_policy_in(&txn, &policy, &room)? {
            return self.room_audience_members_in_txn(&txn, room);
        }
        if !read.reaches_by_membership_in(&txn, &room)? {
            return Err(Error::EntityNotFound);
        }
        self.room_audience_members_in_txn(&txn, room)
            .ok()
            .filter(|members| member.is_some_and(|id| members.contains(&id)))
            .ok_or(Error::EntityNotFound)
    }

    /// [`Self::room_audience_members`] in the caller's snapshot.
    pub(crate) fn room_audience_members_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
    ) -> Result<Vec<EntityId>> {
        match project_room_of(self, txn, room)? {
            Some(room) => room
                .member_ids
                .iter()
                .map(|id| EntityId::from_hex(id))
                .collect(),
            None => self.members_in_txn(txn, room),
        }
    }

    /// Host roster configuration, not a user message. A platform handle maps
    /// to exactly one present actor. The mapping never creates grants.
    pub fn bind_room_handle(&self, room: EntityId, handle: &str, actor: EntityId) -> Result<()> {
        if handle.is_empty() || handle.len() > 256 || handle.contains('\0') {
            return Err(invalid());
        }
        self.with_write_txn_grouped(|txn| {
            // A handle may name an agent with no seat: naming enrolls no one
            // and grants nothing (OF-529). A person stands on its seat or a
            // live Ready join for the room (OF-417).
            let record = room_in(self, txn, room)?;
            let now = self.store.clock.now_recorded_at();
            let subject = participation::participant_in_txn(self, txn, actor, now)?;
            if !record.member_ids.contains(&actor.to_hex())
                && !participation::addressable_agent_in_txn(self, txn, actor, now)?
                && !participation::person_stands_in_txn(self, txn, room, None, actor, subject)?
            {
                return Err(invalid());
            }
            HANDLES.put(&self.store, txn, &(room, handle.to_owned()), &actor)?;
            Ok(())
        })?;
        // FIX 1794: the binding reaches the room's live window.
        #[cfg(feature = "sync")]
        self.refresh_room_cell_in_live_window(room, Some(handle));
        Ok(())
    }
}
impl Memory<'_> {
    /// The caller's rooms whose record its own grants admit and whose Scope
    /// reads base reality, where room records live. Inside a room turn, only
    /// that room.
    pub fn rooms_list(&self) -> MemoryResult<Vec<(EntityId, ProjectRoom)>> {
        if let Some(turn) = self.room_turn() {
            let room = turn.room;
            if !self.room_record_readable(room)? || !turns_readable(&self.room_read_worlds(room)?) {
                return Ok(Vec::new());
            }
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            return Ok(vec![(
                room,
                require_reader(self.vault(), &txn, room, self.actor())?,
            )]);
        }
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        // OF-529: an agent also lists the rooms a Ready receipt admits it to.
        let subject = participation::participant_in_txn(
            self.vault(),
            &txn,
            self.actor(),
            self.vault().store.clock.now_recorded_at(),
        )?;
        let mut result = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.vault().store,
            &txn,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            None,
        )? {
            let id = row?;
            if let Ok(room) = room_in(self.vault(), &txn, id)
                && participation::reads_room_in_txn(
                    self.vault(),
                    &txn,
                    id,
                    &room,
                    self.actor(),
                    subject,
                )?
            {
                result.push((id, room));
            }
        }
        drop(txn);
        let mut readable = Vec::with_capacity(result.len());
        for (id, room) in result {
            if self.room_record_readable(id)? && turns_readable(&self.room_read_worlds(id)?) {
                readable.push((id, room));
            }
        }
        Ok(readable)
    }
    pub fn rooms_claim(
        &self,
        room: EntityId,
        turn: EntityId,
        now: u64,
    ) -> MemoryResult<RoomClaimOutcome> {
        // OF-529: a person claims from its seat, as before; an agent on a
        // Ready receipt for the turn's thread or the room. Checked before
        // the room's scope is read, and again in the writer.
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let claimed = turn_in(self.vault(), &txn, turn)?;
        if claimed.room_id != room.to_hex() {
            return Err(MemoryError::from(invalid()));
        }
        Claimant::admit_in_txn(self.vault(), &txn, room, &claimed, self.actor())?;
        drop(txn);
        if !turns_readable(&self.room_read_worlds(room)?) {
            return Err(outside_scope());
        }
        // A claim names who holds the turn, so the turn must be one this
        // caller may read.
        if self.admitted_turns(vec![claimed])?.is_empty() {
            return Err(MemoryError::from(invalid()));
        }
        let outcome = self.with_verified_actor_write_txn(|txn| {
            let addressed = turn_in(self.vault(), txn, turn)?;
            if addressed.room_id != room.to_hex() {
                return Err(MemoryError::from(invalid()));
            }
            let claimant =
                Claimant::admit_in_txn(self.vault(), txn, room, &addressed, self.actor())?;
            // Claiming a turn is speaking: engine upkeep holds no speaking
            // role, and winning the turn appoints no host.
            claimant.admit_speech_in(self.vault(), txn)?;
            // An agent holding the thread's open task counts as addressed.
            // An agent speaks only when it is addressed or holds a task
            // there (ARCH-0006a, ruled 2026-09-23), so it claims no turn
            // that names no one either; a person still may.
            let named = addressed.addressed_agents.contains(&self.actor().to_hex());
            let task = claimant.held_task_in_txn(self.vault(), txn, &addressed)?;
            if (claimant.is_agent() || !addressed.addressed_agents.is_empty())
                && !named
                && task.is_none()
            {
                return Ok(RoomClaimOutcome::NotAddressed);
            }
            if let Some(claim) = CLAIMS.get(&self.vault().store, txn, &turn)? {
                if claim.actor != self.actor().to_hex() {
                    return Ok(RoomClaimOutcome::HeldBy(claim));
                }
                claimant.record_in_txn(self.vault(), txn, turn, named, task)?;
                return Ok(RoomClaimOutcome::Claimed(claim));
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
            claimant.record_in_txn(self.vault(), txn, turn, named, task)?;
            Ok(RoomClaimOutcome::Claimed(receipt))
        })?;
        // FIX 1794: the claim, and the facts it recorded, reach the live
        // windows that carry them.
        #[cfg(feature = "sync")]
        self.vault().refresh_room_turn_facts_in_live_windows(turn);
        Ok(outcome)
    }
    /// Uses the normal witness gate. The common witness transaction verifies
    /// the claim, membership, reply binding, and addressing before any message.
    pub fn rooms_speak(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        let room = EntityId::from_hex(&turn.conversation_ref)?;
        // OF-529: an agent speaks on a Ready receipt, checked before the
        // room's scope is read; a person from its seat, as before.
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        participation::require_speaker_in_txn(self.vault(), &txn, room, turn, self.actor())?;
        drop(txn);
        if !turns_readable(&self.room_read_worlds(room)?) {
            return Err(outside_scope());
        }
        self.witness(turn)
    }
}
