//! A room turn (ARCH-0067 §8): one actor's reads inside one room's Scope.

use super::*;
use crate::EntityId;
use crate::claim::ScopedReadResult;

/// What a host hands an agent for one turn in a room. Every read runs through
/// the facade's read lane inside `room_scope(roster)` for the room's current
/// roster, and each row must be one every member may read. A turn offers no
/// door that reads around that lane, so it is a narrower handle than
/// [`Memory`], never a wider one.
pub struct RoomTurnHandle<'v> {
    pub(super) memory: Memory<'v>,
}

/// The SDK verbs a room turn serves: `vault.recall`, which reads through the
/// lane, and the room verbs themselves. Every other verb is refused inside a turn.
const ROOM_TURN_VERBS: &[&str] = &[
    "report",
    "vault.recall",
    "vault.rooms.list",
    "vault.rooms.messages",
    "vault.rooms.render",
    "vault.rooms.find",
    "vault.rooms.get",
    "vault.rooms.trunk",
    "vault.rooms.reply_strips",
    "vault.rooms.claim",
    "vault.rooms.speak",
    "vault.rooms.offer",
    "vault.rooms.host",
    "vault.rooms.host.hand",
    "vault.rooms.sharing",
    "vault.rooms.participants",
];

impl<'v> RoomTurnHandle<'v> {
    /// The room this turn runs in.
    #[must_use]
    pub fn room(&self) -> EntityId {
        self.memory
            .room_turn()
            .expect("a room turn is always bound")
            .room
    }

    /// The Scope this turn reads inside now.
    pub fn scope(&self) -> MemoryResult<crate::federation::Scope> {
        self.memory.room_read_scope(self.room())
    }

    /// Whether a turn serves `verb`. A host refuses any other verb before it
    /// looks anything up for it.
    #[must_use]
    pub fn serves(verb: &str) -> bool {
        ROOM_TURN_VERBS.contains(&verb)
    }

    /// One SDK verb inside the turn; a verb that could read around the room
    /// is refused rather than run unbound.
    pub fn invoke(&self, verb: &str, input: serde_json::Value) -> MemoryResult<serde_json::Value> {
        if !Self::serves(verb) {
            return Err(MemoryError::bad_request_with(
                format!("{verb} is not served inside a room turn"),
                &["Call it outside the room turn."],
            ));
        }
        crate::task_verb::sdk::invoke(&self.memory, verb, input)
    }

    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&crate::llm::BudgetLease>,
    ) -> MemoryResult<MemoryPack> {
        self.memory
            .recall(query, effort, scope, limit, format, lease)
    }

    /// The `vault.recall` verb with the query vector `embed` returns, for a host
    /// that embeds the query; it reads through the same lane as
    /// [`Self::invoke`].
    pub fn recall_with_vector(
        &self,
        input: crate::task_verb::sdk::RecallRequest,
        embed: impl FnOnce(&str) -> Option<Vec<f32>>,
    ) -> MemoryResult<MemoryPack> {
        crate::task_verb::sdk::recall_with_vector(&self.memory, input, embed)
    }

    /// [`Self::recall_with_vector`] whose deadline counts from the door's
    /// arrival; see [`crate::task_verb::sdk::recall_at_door`].
    pub fn recall_at_door(
        &self,
        input: crate::task_verb::sdk::RecallRequest,
        embed: impl FnOnce(&str) -> Option<Vec<f32>>,
        door: &crate::task_verb::sdk::RecallDoor<'_>,
    ) -> MemoryResult<MemoryPack> {
        crate::task_verb::sdk::recall_at_door(&self.memory, input, embed, door)
    }

    /// [`Self::recall_at_door`] whose host may also embed the query into
    /// declared spaces; see [`crate::task_verb::sdk::recall_at_door_seeded`].
    pub fn recall_at_door_seeded(
        &self,
        input: crate::task_verb::sdk::RecallRequest,
        embed: impl FnOnce(&str) -> crate::retrieval_depth::RecallQueryVectors,
        door: &crate::task_verb::sdk::RecallDoor<'_>,
    ) -> MemoryResult<MemoryPack> {
        crate::task_verb::sdk::recall_at_door_seeded(&self.memory, input, embed, door)
    }

    pub fn get_entity(
        &self,
        entity_ref: &str,
    ) -> MemoryResult<ScopedReadResult<Option<EntityView>>> {
        self.memory.get_entity(entity_ref)
    }

    pub fn hydrate(&self, refs: &[String]) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        self.memory.hydrate(refs)
    }

    pub fn claim_list(
        &self,
        filter: &ClaimListFilter,
    ) -> MemoryResult<ScopedReadResult<Vec<ClaimView>>> {
        self.memory.claim_list(filter)
    }

    pub fn rooms_messages(&self) -> MemoryResult<Vec<crate::workspace_roster::RoomTurn>> {
        self.memory.rooms_messages(self.room())
    }

    pub fn rooms_render(&self) -> MemoryResult<crate::context_board::RoomSection> {
        self.memory.rooms_render(self.room())
    }

    /// Speaks into this turn's room; any other room is refused.
    pub fn rooms_speak(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        self.memory.rooms_speak(turn)
    }

    /// The bound facade, for engine doors that already read through the lane.
    pub(crate) fn memory(&self) -> &Memory<'v> {
        &self.memory
    }
}

impl<'v> Memory<'v> {
    /// The room's own reads for this actor: its turn when this handle is
    /// bound to one, else the member's own read of the room. That keeps a
    /// turn's world, audience and peer gates and holds no row to P7, which
    /// binds a turn: outside one the read stays the member's own.
    pub(crate) fn for_room_projection(&self, room: EntityId) -> MemoryResult<RoomTurnHandle<'v>> {
        let mut handle = self.for_room_turn(room)?;
        if self.room_turn.is_none()
            && let Some(turn) = handle.memory.room_turn.as_mut()
        {
            turn.terms = crate::claim::TurnTerms::new(crate::claim::RoomTerms {
                clearance: None,
                p7: false,
                ..turn.terms.get()
            });
        }
        Ok(handle)
    }

    /// The reads of thread `thread` of `room` for this actor (OF-529): the
    /// turn's world, facet, audience, peer and P7 gates under the ceiling
    /// that thread puts on it ([`Self::thread_ceiling`]), met into the turn
    /// this handle is bound to, if any. An agent standing on that thread's
    /// own Ready receipt reads it this way without a seat, and reads nothing
    /// else of the room. Unlike [`Self::for_room_projection`], P7 binds it
    /// outside a turn too: a thread's reader is no member reading its own.
    pub(crate) fn for_thread_projection(
        &self,
        room: EntityId,
        thread: EntityId,
    ) -> MemoryResult<RoomTurnHandle<'v>> {
        self.verified_actor_class()?;
        self.require_room_in_facets(room)?;
        let ceiling = self.thread_ceiling(room, thread)?;
        Ok(RoomTurnHandle {
            memory: Memory {
                vault: self.vault,
                actor: self.actor,
                actor_class: self.actor_class,
                session_key: self.session_key,
                machine_signer: self.machine_signer,
                read_proof: self.read_proof.clone(),
                room_turn: Some(ceiling),
                host_origin: self.host_origin.clone(),
                locality: self.locality,
                producers: self.producers,
                birth_position: self.birth_position,
                // A thread's read writes nothing as the owner in person.
                owner_authorship: None,
                invocation: self.invocation,
                invocation_slip: self.invocation_slip.clone(),
                transport_invocation: self.transport_invocation,
                task_grant: self.task_grant,
                origin_conversation: self.origin_conversation,
                task_host: None,
                off_record_session: self.off_record_session.clone(),
                credential: self.credential,
                credential_instrument: self.credential_instrument.clone(),
                credential_door: self.credential_door.clone(),
                rewrite_admit: self.rewrite_admit.clone(),
            },
        })
    }
}
