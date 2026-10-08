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

/// The SDK verbs a room turn serves: recall, which reads through the lane,
/// and the room verbs themselves. Every other verb is refused inside a turn.
const ROOM_TURN_VERBS: &[&str] = &[
    "recall",
    "rooms.list",
    "rooms.messages",
    "rooms.render",
    "rooms.find",
    "rooms.get",
    "rooms.trunk",
    "rooms.claim",
    "rooms.speak",
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
