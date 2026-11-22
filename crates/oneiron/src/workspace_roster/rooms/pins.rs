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
//!
//! An unpin keeps the records it removed beside the list
//! (ROOM-PINS-LWW-MERGE; RULED ROOM-PIN-CONCURRENT-UNPIN = A, add-wins): a
//! vault's machines merge their copies of a room record by record
//! ([`crate::store::conversation_body::merge_room_pins`]), so an unpin
//! removes only the records it saw and a pin another machine made meanwhile
//! stays.
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

    /// The pin records an unpin removed, which a merge never brings back.
    fn unpinned(&self) -> &[RoomPin] {
        match self {
            Self::Room(body) => &body.unpinned,
            Self::Home(body) => &body.unpinned,
        }
    }

    fn unpinned_mut(&mut self) -> &mut Vec<RoomPin> {
        match self {
            Self::Room(body) => &mut body.unpinned,
            Self::Home(body) => &mut body.unpinned,
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
                crate::store::conversation_body::validate_room_pins(&body.pins, &body.unpinned)?;
                crate::store::conversation_body::encode(body)?
            }
        };
        PIN_UPDATES.put(&vault.store, txn, &room, &[1])?;
        put_room_body_in(vault, txn, room, &bytes)?;
        PIN_UPDATES.delete(&vault.store, txn, &room)?;
        Ok(())
    }
}

/// Writes `bytes` as `room`'s body, keeping the room's header times, in the
/// caller's write transaction. The door that calls it sets its own marker
/// around the write, as the all-writer guard asks.
pub(super) fn put_room_body_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    bytes: &[u8],
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)?
        .ok_or(Error::EntityNotFound)?;
    if raw.len() < ENTITY_METADATA_HEADER_LEN {
        return Err(Error::CorruptedIndex("conversation header"));
    }
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("conversation header"))?;
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
            bytes,
        )
        .apply(txn)?;
    Ok(())
}

/// The pins `room`'s stored body holds, one record per target
/// ([`crate::store::conversation_body::live_room_pins`]), in their stored
/// order, as `txn` reads them (ROOM-SCOPED-PINS P2). Only the room's admitted
/// projection reads them, and it serves a pin only when the reader admits its
/// target; the list itself is never served.
pub(crate) fn stored_room_pins_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Vec<RoomPin>> {
    Ok(crate::store::conversation_body::live_room_pins(
        PinnedBody::read_in(vault, txn, room)?.pins(),
    ))
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

/// Whether `caller` sets `room`'s pin policy, read in `txn`: only a person
/// who runs the room ([`manager_in`]), never an agent. Answers the stored
/// body the policy lives on.
fn policy_setter_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
) -> Result<PinnedBody> {
    if caller.actor_class() != EdgeActorClass::Human {
        return Err(lacks(POLICY_BY_PERSON));
    }
    let body = PinnedBody::read_in(vault, txn, room)?;
    if !manager_in(vault, txn, room, caller.entity_ref(), true, body.home())? {
        return Err(lacks(NOT_ROOM_MANAGER));
    }
    Ok(body)
}

/// Whether `caller` may change `room`'s pins and their unpin records from
/// `held`'s to `body`'s, read in `txn` against the stored body as the pin and
/// unpin doors read it ([`pin_writer_in`]). A federation peer's room body is
/// judged by it, without the doors' write-actor check: the peer's grant
/// authenticated its sender (ROOM-BODY-REPLICA-SETTINGS). An unpin moves a
/// held pin's record as it is; any other record `body` adds, one `held` holds
/// neither as a pin nor as an unpin record, is a pin the sender made, so it
/// must name the writer the pin door writes for `caller` ([`made_by`]).
#[cfg(feature = "sync")]
pub(super) fn changes_pins_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
    held: &ConversationBody,
    body: &ConversationBody,
) -> Result<bool> {
    let stored = PinnedBody::read_in(vault, txn, room)?;
    let writer = match pin_writer_in(vault, txn, room, caller, &stored) {
        Ok(writer) => writer,
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => return Ok(false),
        Err(error) => return Err(error),
    };
    for record in body.pins.iter().chain(&body.unpinned) {
        if held.pins.contains(record) || held.unpinned.contains(record) {
            continue;
        }
        if !made_by(vault, txn, record, writer)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `record`, a pin a federation peer's room body adds, names
/// `writer`: the PERSON and acting agent the pin door writes for the peer's
/// sender ([`pin_writer_in`]). The PERSON must match, and so must the agent
/// when an agent sends. A PERSON's update may also carry a pin made by one of
/// its own agents: an agent this vault reads as that PERSON's pen.
#[cfg(feature = "sync")]
fn made_by(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &RoomPin,
    (person, agent): (EntityId, Option<EntityId>),
) -> Result<bool> {
    if record.pinned_by != person {
        return Ok(false);
    }
    Ok(match (agent, record.acting_agent) {
        (Some(agent), acting) => acting == Some(agent),
        (None, None) => true,
        (None, Some(acting)) => {
            let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
            acting != person && person_of_actor_in_txn(vault, txn, acting, at)? == Some(person)
        }
    })
}

/// Whether `caller` may set `room`'s pin policy, read in `txn` as the policy
/// door reads it ([`policy_setter_in`]), for a federation peer's room body
/// as [`changes_pins_in`].
#[cfg(feature = "sync")]
pub(super) fn sets_pin_policy_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
) -> Result<bool> {
    granted(policy_setter_in(vault, txn, room, caller).map(drop))
}

/// A pin door's refusal ([`lacks`]) as `false`; any other error stays one.
#[cfg(feature = "sync")]
fn granted(check: Result<()>) -> Result<bool> {
    match check {
        Ok(()) => Ok(true),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => Ok(false),
        Err(error) => Err(error),
    }
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
    /// found, even one pinned already (PIN-RETRY-HIDDEN-TARGET = A, Engine
    /// 17 Nov 00:11). A target pinned already keeps its first record, which
    /// a caller who reads it gets back; that retry changes nothing, so it
    /// marks no room cell for sync.
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
        let (pin, changed) = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = PinnedBody::read_in(vault, txn, input.room)?;
            let (person, agent) = pin_writer_in(vault, txn, input.room, caller, &body)?;
            if let Some(pin) = body.pins().iter().find(|pin| pin.target == input.target) {
                return Ok::<_, MemoryError>((pin.clone(), false));
            }
            let mut pin = RoomPin {
                target: input.target,
                pinned_by: person,
                acting_agent: agent,
                pinned_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
            };
            // A record is pinned once: one the room unpinned never comes
            // back, so a pin in the same second as an unpin of its twin
            // takes the next second (ROOM-PINS-LWW-MERGE).
            while body.unpinned().contains(&pin) {
                pin.pinned_at += 1;
            }
            body.pins_mut().push(pin.clone());
            body.write_in(vault, txn, input.room)?;
            Ok((pin, true))
        })?;
        // FIX ROOM-PINS-NOOP-MARKS-DIRTY: only a change marks the room's cell
        // and queues its flush, as unpin does.
        #[cfg(feature = "sync")]
        if changed {
            vault.refresh_room_cell_in_live_window(input.room, None);
        }
        #[cfg(not(feature = "sync"))]
        let _ = changed;
        Ok(RoomPinReply {
            room: input.room,
            pin,
        })
    }

    /// `vault.rooms.pins.unpin`: removes `target` from `room`'s shared pins,
    /// whoever pinned it, under the same writer rule as a pin. It reads no
    /// target, so a deleted or hidden target can still be removed, and it
    /// answers the same whether or not the target was pinned. The records it
    /// removed stay unpinned: a merge with another machine's copy drops them
    /// there too, and keeps any record of the target this unpin never saw.
    pub fn rooms_pins_unpin(&self, input: &RoomPinRequest) -> MemoryResult<RoomUnpinReply> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        let changed = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = PinnedBody::read_in(vault, txn, input.room)?;
            pin_writer_in(vault, txn, input.room, caller, &body)?;
            let (removed, kept): (Vec<RoomPin>, Vec<RoomPin>) = body
                .pins()
                .iter()
                .cloned()
                .partition(|pin| pin.target == input.target);
            if removed.is_empty() {
                return Ok::<_, MemoryError>(false);
            }
            *body.pins_mut() = kept;
            body.unpinned_mut().extend(removed);
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
        let (policy, changed) = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = policy_setter_in(vault, txn, input.room, caller)?;
            let changed = body.policy() != input.policy;
            if changed {
                body.set_policy(input.policy);
                body.write_in(vault, txn, input.room)?;
            }
            Ok::<_, MemoryError>((body.policy(), changed))
        })?;
        #[cfg(feature = "sync")]
        if changed {
            vault.refresh_room_cell_in_live_window(input.room, None);
        }
        #[cfg(not(feature = "sync"))]
        let _ = changed;
        Ok(RoomPinPolicySet {
            room: input.room,
            policy,
        })
    }
}

/// The pin doors' admissions, read only, for `can({verb})` (FIX
/// [UI-GATE-PREVIEW]): each meets the checks its door meets, in its order,
/// in read transactions, and writes nothing. The door checks all of it
/// again in its own write transaction.
impl Memory<'_> {
    /// `vault.rooms.pins.pin`'s admission: the bound room turn, the writer
    /// rule ([`pin_writer_in`]), the target read through the room's lane,
    /// then the writer's own standing.
    pub(crate) fn rooms_pins_pin_admission(&self, input: &RoomPinRequest) -> MemoryResult<()> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let body = PinnedBody::read_in(vault, &txn, input.room)?;
            pin_writer_in(vault, &txn, input.room, caller, &body)?;
        }
        // The preflight reader (FIX 22102): the pin's own lane, scope and
        // admission, its grants judged at the snapshot's authority instant,
        // so the preview persists no grant time. The pin reads to serve.
        if self
            .for_room_turn(input.room)?
            .memory()
            .peek_entity(&input.target.to_hex())?
            .value
            .is_none()
        {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        vault.verify_write_actor_in_txn(&txn, &caller)?;
        Ok(())
    }

    /// `vault.rooms.pins.unpin`'s admission: the bound room turn, the
    /// writer's own standing, then the writer rule ([`pin_writer_in`]). It
    /// reads no target, as the door reads none.
    pub(crate) fn rooms_pins_unpin_admission(&self, input: &RoomPinRequest) -> MemoryResult<()> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        vault.verify_write_actor_in_txn(&txn, &caller)?;
        let body = PinnedBody::read_in(vault, &txn, input.room)?;
        pin_writer_in(vault, &txn, input.room, caller, &body)?;
        Ok(())
    }

    /// `vault.rooms.pins.policy.set`'s admission: the bound room turn, the
    /// writer's own standing, then [`policy_setter_in`].
    pub(crate) fn rooms_pins_policy_set_admission(
        &self,
        input: &RoomPinPolicySet,
    ) -> MemoryResult<()> {
        self.require_pin_room(input.room)?;
        let vault = self.vault();
        let caller = self.write_actor();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        vault.verify_write_actor_in_txn(&txn, &caller)?;
        policy_setter_in(vault, &txn, input.room, caller)?;
        Ok(())
    }
}
