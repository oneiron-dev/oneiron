//! A room's shared pins (ROOM-SCOPED-PINS; owner 12 Nov 00:04, ROOM-PIN-WRITERS
//! = A; Engine ruling THREADTASK-PINS-SHAPE 00:51).
//!
//! Any current member pins and unpins the room's shared pins. An agent does
//! so only as its pen PERSON's delegate ([`person_of_actor_in_txn`]), never
//! beyond that PERSON: an agent that is no PERSON's pen is refused, even when
//! it is seated in the room. The room's owner or admin may restrict pinning to
//! the room's managers, who are the people who run it: Owner or Admin in an
//! ordinary room, the project's leader and board seats in a home room. Each
//! pin records the PERSON, the acting agent and the engine time. The list
//! lives on the room body and changes only through these doors
//! ([`crate::conversation::PIN_UPDATES`]). A pin moves its target into the
//! PINNED tier of the boards that work in the room; it grants no read.
use super::*;
use crate::EdgeActorClass;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::{ConversationBody, PIN_UPDATES, RoomPin, RoomPinPolicy, RoomRole};
use crate::error::ClaimError;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::workspace_roster::join_consent::person_of_actor_in_txn;
use crate::write_envelope::WriteActor;

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::rooms::pins::{
    RoomPinPolicySet, RoomPinReply, RoomPinRequest, RoomUnpinReply,
};

fn lacks(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

const NO_PEN: &str = "an agent changes a room's pins only as its pen PERSON's delegate, and this agent is no PERSON's pen";
const NOT_MEMBER: &str =
    "only a current member of the room, or that member's agent, changes the room's pins";
const NOT_MANAGER: &str = "this room lets only its managers change its pins";
const NOT_ROOM_MANAGER: &str =
    "only the room's owner or admin, or a home room's project leader or board, sets who may pin";
const POLICY_BY_PERSON: &str = "a person sets the room's pin policy, never an agent";

/// The stored body a room's pins live on: an ordinary room's
/// [`ConversationBody`], or a home room's own stored [`ProjectRoom`] (never
/// the effective-seat view [`room_in`] returns).
enum PinnedBody {
    Room(ConversationBody),
    Home(ProjectRoom),
}

impl PinnedBody {
    fn read_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<Self> {
        if project_room_of(vault, txn, room)?.is_some() {
            let stored = super::super::project::record::<ProjectRoom>(
                &vault.store,
                txn,
                room,
                ENTITY_TYPE_CONVERSATION,
            )?
            .ok_or(Error::EntityNotFound)?;
            return Ok(Self::Home(stored));
        }
        Ok(Self::Room(crate::conversation::body_in(vault, txn, room)?))
    }

    fn pins(&self) -> &[RoomPin] {
        match self {
            Self::Room(body) => &body.pins,
            Self::Home(body) => &body.pins,
        }
    }

    fn pins_mut(&mut self) -> &mut Vec<RoomPin> {
        match self {
            Self::Room(body) => &mut body.pins,
            Self::Home(body) => &mut body.pins,
        }
    }

    fn policy(&self) -> RoomPinPolicy {
        match self {
            Self::Room(body) => body.pin_policy,
            Self::Home(body) => body.pin_policy,
        }
    }

    fn set_policy(&mut self, policy: RoomPinPolicy) {
        match self {
            Self::Room(body) => body.pin_policy = policy,
            Self::Home(body) => body.pin_policy = policy,
        }
    }

    fn home(&self) -> Option<&ProjectRoom> {
        match self {
            Self::Room(_) => None,
            Self::Home(body) => Some(body),
        }
    }

    /// Writes the body back under the pin door's marker, keeping the
    /// room's header times, in the caller's write transaction.
    fn write_in(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>, room: EntityId) -> Result<()> {
        let bytes = match self {
            Self::Room(body) => body.to_bytes()?,
            Self::Home(body) => {
                crate::store::conversation_body::validate_room_pins(&body.pins)?;
                crate::store::conversation_body::encode(body)?
            }
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)?
            .ok_or(Error::EntityNotFound)?;
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("conversation header"));
        }
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("conversation header"))?;
        PIN_UPDATES.put(&vault.store, txn, &room, &[1])?;
        vault
            .batch_in()
            .put(
                &room,
                ENTITY_TYPE_CONVERSATION,
                crate::TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &bytes,
            )
            .apply(txn)?;
        PIN_UPDATES.delete(&vault.store, txn, &room)?;
        Ok(())
    }
}

/// The pins `room`'s stored body holds, in their stored order, as `txn`
/// reads them (ROOM-SCOPED-PINS P2). Only the room's admitted projection
/// reads them, and it serves a pin only when the reader admits its target;
/// the list itself is never served.
pub(crate) fn stored_room_pins_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Vec<RoomPin>> {
    Ok(PinnedBody::read_in(vault, txn, room)?.pins().to_vec())
}

/// Whether `person` runs `room`: Owner or Admin in an ordinary room
/// ([`crate::conversation::person_role_in`]), a seated project leader or
/// board member in a home room. `human`: whether the PERSON acts as a human.
fn manager_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
    human: bool,
    home: Option<&ProjectRoom>,
) -> Result<bool> {
    let Some(home) = home else {
        return Ok(matches!(
            crate::conversation::person_role_in(vault, txn, room, person, human),
            Ok(RoomRole::Owner | RoomRole::Admin)
        ));
    };
    let project = EntityId::from_hex(&home.project_id)?;
    let Some((project, effective)) = vault.effective_project_in_txn(txn, project)? else {
        return Ok(false);
    };
    let seat = person.to_hex();
    Ok(effective.seats(&seat) && (project.leader == seat || project.board.contains(&seat)))
}

/// Who changes `room`'s pins for `caller`: the PERSON it is, or whose pen it
/// is, and the acting agent when an agent acts. Refused unless that PERSON
/// is a current member and, under [`RoomPinPolicy::Managers`], one of the
/// room's managers.
fn pin_writer_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
    body: &PinnedBody,
) -> Result<(EntityId, Option<EntityId>)> {
    let actor = caller.entity_ref();
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let person = person_of_actor_in_txn(vault, txn, actor, at)?.ok_or_else(|| lacks(NO_PEN))?;
    let agent = (person != actor).then_some(actor);
    if !vault
        .room_audience_members_in_txn(txn, room)?
        .contains(&person)
    {
        return Err(lacks(NOT_MEMBER));
    }
    let human = agent.is_some() || caller.actor_class() == EdgeActorClass::Human;
    if body.policy() == RoomPinPolicy::Managers
        && !manager_in(vault, txn, room, person, human, body.home())?
    {
        return Err(lacks(NOT_MANAGER));
    }
    Ok((person, agent))
}

impl Memory<'_> {
    /// An agent bound to a room turn changes only that room's pins.
    fn require_pin_room(&self, room: EntityId) -> MemoryResult<()> {
        if self.room_turn().is_some_and(|turn| turn.room != room) {
            return Err(MemoryError::bad_request_with(
                "room differs from the bound room turn",
                &["Pin inside the room the turn is bound to."],
            ));
        }
        Ok(())
    }

    /// `vault.rooms.pins.pin`: pins `target` in `room`'s shared pins for the
    /// caller, a current member or its pen agent ([`pin_writer_in`]). The
    /// caller must read the target through the room's own lane
    /// ([`Memory::for_room_turn`]); a target it cannot read answers as not
    /// found. A target pinned already keeps its first record.
    pub fn rooms_pins_pin(&self, input: &RoomPinRequest) -> MemoryResult<RoomPinReply> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let body = PinnedBody::read_in(vault, &txn, input.room)?;
            pin_writer_in(vault, &txn, input.room, caller, &body)?;
        }
        if self
            .for_room_turn(input.room)?
            .get_entity(&input.target.to_hex())?
            .value
            .is_none()
        {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        let pin = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = PinnedBody::read_in(vault, txn, input.room)?;
            let (person, agent) = pin_writer_in(vault, txn, input.room, caller, &body)?;
            if let Some(pin) = body.pins().iter().find(|pin| pin.target == input.target) {
                return Ok::<_, MemoryError>(pin.clone());
            }
            let pin = RoomPin {
                target: input.target,
                pinned_by: person,
                acting_agent: agent,
                pinned_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
            };
            body.pins_mut().push(pin.clone());
            body.write_in(vault, txn, input.room)?;
            Ok(pin)
        })?;
        #[cfg(feature = "sync")]
        vault.refresh_room_cell_in_live_window(input.room, None);
        Ok(RoomPinReply {
            room: input.room,
            pin,
        })
    }

    /// `vault.rooms.pins.unpin`: removes `target` from `room`'s shared pins,
    /// whoever pinned it, under the same writer rule as a pin. It reads no
    /// target, so a deleted or hidden target can still be removed, and it
    /// answers the same whether or not the target was pinned.
    pub fn rooms_pins_unpin(&self, input: &RoomPinRequest) -> MemoryResult<RoomUnpinReply> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        let changed = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = PinnedBody::read_in(vault, txn, input.room)?;
            pin_writer_in(vault, txn, input.room, caller, &body)?;
            let before = body.pins().len();
            body.pins_mut().retain(|pin| pin.target != input.target);
            if body.pins().len() == before {
                return Ok::<_, MemoryError>(false);
            }
            body.write_in(vault, txn, input.room)?;
            Ok(true)
        })?;
        #[cfg(feature = "sync")]
        if changed {
            vault.refresh_room_cell_in_live_window(input.room, None);
        }
        #[cfg(not(feature = "sync"))]
        let _ = changed;
        Ok(RoomUnpinReply { room: input.room })
    }

    /// `vault.rooms.pins.policy.set`: sets who may change `room`'s pins. Only
    /// a person who runs the room sets it ([`manager_in`]); an agent never
    /// does.
    pub fn rooms_pins_policy_set(
        &self,
        input: &RoomPinPolicySet,
    ) -> MemoryResult<RoomPinPolicySet> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        let policy = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            if caller.actor_class() != EdgeActorClass::Human {
                return Err(MemoryError::from(lacks(POLICY_BY_PERSON)));
            }
            let mut body = PinnedBody::read_in(vault, txn, input.room)?;
            if !manager_in(
                vault,
                txn,
                input.room,
                caller.entity_ref(),
                true,
                body.home(),
            )? {
                return Err(MemoryError::from(lacks(NOT_ROOM_MANAGER)));
            }
            if body.policy() != input.policy {
                body.set_policy(input.policy);
                body.write_in(vault, txn, input.room)?;
            }
            Ok(body.policy())
        })?;
        #[cfg(feature = "sync")]
        vault.refresh_room_cell_in_live_window(input.room, None);
        Ok(RoomPinPolicySet {
            room: input.room,
            policy,
        })
    }
}
