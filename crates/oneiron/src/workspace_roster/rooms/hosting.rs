//! Room hosting: the speaking duty, kept apart from the engine's upkeep.
//!
//! The engine performs every room's mechanical upkeep and a host does the
//! speaking part (ARCH-0067 §8). Only an agent hosts (owner ruling, OF-528):
//! an AGENT_DEF that speaks as a persona and stands in the room, on its seat
//! or a covering Ready receipt (OF-529). A person never hosts, nor does a
//! companion acting as its PERSON. An AGENT_DEF anchored to a PERSON is that
//! person's pen: a human's pen never hosts, and a companion's pen (its PERSON
//! is model-backed) hosts as the agent it is. The Dreamer, the Coach and
//! every MACHINE never host. A room with no agent here, such as a
//! humans-only room, has no host: it is a plain chatroom with the engine's
//! roster, receipts and needs-you strip.
//!
//! Who hosts, in order:
//! 1. The room's stored host: the latest pin, by someone the room's grant
//!    allows (its owner, or a delegate holding its delegate action: the party
//!    that admits to the room, OF-531), or the latest handoff, by the host it
//!    replaced. It wins outright, present or not, while its agent may still
//!    host. Otherwise it is passed over, and never deleted on read.
//! 2. Of the leaders present, the nearest: the room's own project first, then
//!    each ring of ancestors from the signed project fold. On a tie, the one
//!    present first.
//! 3. With no leader present, the agent present first.
//!
//! Presence is a session's live participants in arrival order, met with
//! who may host; no request names it. Hosting is a speaking duty only: it
//! grants no scope, no room role, no admission and no turn, and a host is
//! never an admission party.
use super::participation::{agent_standing_in_txn, participant_in_txn, person_standing_in_txn};
use super::*;
use crate::conversation::room_host_in_txn;
use crate::error::{ClaimError, RecordError};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::side_table::Named;
use crate::store::Store;
use crate::workspace_roster::join_consent::JoinSubject;
use crate::{EdgeActorClass, WriteActor};

/// How a member speaks in a room. Engine upkeep holds neither role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoomSpeakingRole {
    /// Holds the room's speaking duty.
    Host,
    /// Speaks when addressed, or when its posture lets it chime in.
    Member,
}

/// How a room's stored host came to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostPinKind {
    /// Someone the room's grant allows pinned it.
    Pinned,
    /// The room's host handed the duty on.
    HandedOff,
}

/// A room's stored host: the latest pin or handoff. It wins outright while
/// its agent may still host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPin {
    pub agent: EntityId,
    /// Who pinned it, or the host who handed it on.
    pub by: EntityId,
    pub kind: HostPinKind,
    /// When it was recorded, on the store's recorded-at clock (unix seconds).
    pub at: u64,
}

/// Each room's stored host, latest write wins. Key: id16 (room).
pub(super) const HOST_PINS: SideTable<EntityId, HostPin, Named> =
    SideTable::new(&side_table::ROOMS_HOST_PIN);

/// Who holds a room's speaking duty now.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomHosting {
    /// The agent holding it; `None` when no agent may, as in a room of
    /// humans only.
    pub host: Option<EntityId>,
    /// The other present agents who may hold it by presence, earliest
    /// arrival first: the nearest present leaders, or every present agent
    /// when no leader is here. Shown, never chosen from.
    pub candidates: Vec<EntityId>,
    /// The stored pin or handoff that chose `host`; `None` when presence
    /// chose it.
    pub pin: Option<HostPin>,
}

/// A member's reading of its room's hosting and of its own speaking role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomStanding {
    pub hosting: RoomHosting,
    /// `None` for an actor that speaks as no persona.
    pub role: Option<RoomSpeakingRole>,
}

/// `vault.rooms.host.pin`: pins `agent` as `room`'s host, or with none
/// clears the room's stored host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostPin {
    pub room: EntityId,
    #[serde(default)]
    pub agent: Option<EntityId>,
}

/// `vault.rooms.host.hand`: the room's current host hands the duty to `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostHand {
    pub room: EntityId,
    pub to: EntityId,
    /// The live session whose participants count as present, as
    /// `vault.rooms.host` reads it. A host by presence must be one of them; a
    /// stored host hands on without one.
    #[serde(default)]
    pub session: Option<EntityId>,
}

fn refused() -> Error {
    Error::Record(RecordError::ConversationDenied)
}

fn lacks(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

/// Whether `actor` speaks as a persona: a live PERSON, or a live AGENT_DEF
/// that is enabled and active. The Dreamer, the Coach and every MACHINE run
/// the engine's upkeep; they have no pen, no diary and no persona.
pub(crate) fn eligible_room_speaker_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<bool> {
    if crate::dreamer_runner::authority::is_base_agent_actor(&actor)?
        || vault.archive_tombstone_in_txn(txn, &actor)?.is_some()
    {
        return Ok(false);
    }
    Ok(
        match crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor)? {
            crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PERSON,
                ..
            } => true,
            crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body,
            } => crate::agent_def::decode_agent_definition(&body).is_ok_and(|def| {
                def.enabled && def.lifecycle_status == crate::claim::ClaimLifecycleStatus::Active
            }),
            _ => false,
        },
    )
}

/// The project a project home room belongs to; `None` for any other room.
pub(crate) fn room_project_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<EntityId>> {
    project_room_of(vault, txn, room)?
        .map(|record| EntityId::from_hex(&record.project_id))
        .transpose()
}

/// Whether `actor` stands in `room` now (OF-529): an agent on its seat or a
/// covering Ready receipt; a person, or a person's pen, on that person's
/// standing. Anything else stands nowhere.
fn stands_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let now = vault.store.clock.now_recorded_at();
    Ok(match participant_in_txn(vault, txn, actor, now)? {
        Some(JoinSubject::Agent(agent)) => {
            agent_standing_in_txn(vault, txn, room, None, agent, None)?.is_some()
        }
        Some(JoinSubject::Person(person)) => {
            let pen = (person != actor).then_some(actor);
            person_standing_in_txn(vault, txn, room, None, person, pen)? == Some(true)
        }
        None => false,
    })
}

/// Whether `actor` stands in `room` and speaks as a persona.
fn persona_member_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    Ok(eligible_room_speaker_in(vault, txn, actor)? && stands_in(vault, txn, room, actor)?)
}

/// Whether `actor` may hold `room`'s host duty: an AGENT_DEF that stands in
/// the room and speaks as a persona. A PERSON never does. An AGENT_DEF
/// anchored to a PERSON is that person, so it hosts only when that PERSON is
/// model-backed (a companion's pen); a human's pen, or one whose substrate is
/// unsettled or malformed, never does.
fn may_host_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &actor)? != Some(ENTITY_TYPE_AGENT_DEF)
        || !persona_member_in(vault, txn, room, actor)?
    {
        return Ok(false);
    }
    let now = vault.store.clock.now_recorded_at();
    let Some(JoinSubject::Person(person)) = participant_in_txn(vault, txn, actor, now)? else {
        return Ok(true);
    };
    match crate::subject_model::person_substrate_in_txn(vault, txn, &person, now) {
        Ok(substrate) => Ok(substrate == Some(crate::subject_model::PersonSubstrate::Model)),
        Err(Error::InvalidClaimBody(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The selection door every host passes: only an agent that stands in
/// `room` and speaks as a persona may hold its host duty. A person, the
/// Dreamer, any other upkeep actor or an agent with no standing there is
/// refused here, typed.
pub(crate) fn admit_room_host_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<()> {
    if !may_host_in(vault, txn, room, actor)? {
        return Err(refused());
    }
    Ok(())
}

/// The speech door for a room turn, claimed or answered: the speaker must
/// hold a speaking role. Hosting is not needed to speak, and winning a turn
/// appoints no host. Upkeep keeps its own write paths and never speaks here.
pub(crate) fn admit_room_speech_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<()> {
    room_speaking_role_in(vault, txn, room, actor, &RoomHosting::default())?
        .map(|_| ())
        .ok_or_else(refused)
}

/// The agents among `present` who may hold `room`'s duty by presence,
/// earliest arrival first: the present leaders of the nearest ring that has
/// one, or every present agent when no leader is here. Leaders come from the
/// signed project fold: the room's own project first, then each ring of
/// ancestors. Order is arrival only, never id or label.
fn present_pool_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    present: &[EntityId],
) -> Result<Vec<EntityId>> {
    let mut named = BTreeSet::new();
    let mut here = Vec::new();
    for actor in present {
        if named.insert(*actor) && may_host_in(vault, txn, room, *actor)? {
            here.push(*actor);
        }
    }
    let agents: BTreeSet<EntityId> = here.iter().copied().collect();
    let mut seen: BTreeSet<EntityId> = room_project_in(vault, txn, room)?.into_iter().collect();
    let mut ring: Vec<EntityId> = seen.iter().copied().collect();
    while !ring.is_empty() {
        let mut leaders = BTreeSet::new();
        let mut next = Vec::new();
        for id in ring {
            let Some((_, effective)) = vault.effective_project_in_txn(txn, id)? else {
                continue;
            };
            let leader = EntityId::from_hex(&effective.leader)?;
            if agents.contains(&leader) {
                leaders.insert(leader);
            }
            for parent in &effective.parents {
                let parent = EntityId::from_hex(parent)?;
                if seen.insert(parent) {
                    next.push(parent);
                }
            }
        }
        if !leaders.is_empty() {
            here.retain(|agent| leaders.contains(agent));
            return Ok(here);
        }
        ring = next;
    }
    Ok(here)
}

/// Who hosts `room` among `present`, earliest arrival first, which the
/// engine resolves and a request never names. The stored pin or handoff
/// holds it while its agent may still host, present or not; otherwise the
/// first of the present pool ([`present_pool_in`]) does. A stored host that
/// may no longer host is passed over and kept.
pub(crate) fn room_host_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    present: &[EntityId],
) -> Result<RoomHosting> {
    let pool = present_pool_in(vault, txn, room, present)?;
    let pin = match HOST_PINS.get(&vault.store, txn, &room)? {
        Some(pin) if may_host_in(vault, txn, room, pin.agent)? => Some(pin),
        _ => None,
    };
    let host = pin
        .as_ref()
        .map(|pin| pin.agent)
        .or_else(|| pool.first().copied());
    Ok(RoomHosting {
        host,
        candidates: pool
            .into_iter()
            .filter(|agent| Some(*agent) != host)
            .collect(),
        pin,
    })
}

/// `actor`'s speaking role in `room` under `hosting`: Host for the selected
/// host, Member for any other member who speaks as a persona, and `None` for
/// upkeep or one with no standing there.
pub(crate) fn room_speaking_role_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
    hosting: &RoomHosting,
) -> Result<Option<RoomSpeakingRole>> {
    if !persona_member_in(vault, txn, room, actor)? {
        return Ok(None);
    }
    Ok(Some(if hosting.host == Some(actor) {
        RoomSpeakingRole::Host
    } else {
        RoomSpeakingRole::Member
    }))
}

/// `actor`'s reading of `room`'s hosting among `present`.
fn standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
    present: &[EntityId],
) -> Result<RoomStanding> {
    let hosting = room_host_in(vault, txn, room, present)?;
    let role = room_speaking_role_in(vault, txn, room, actor, &hosting)?;
    Ok(RoomStanding { hosting, role })
}

/// Deletes a room's stored host, with the room's other rows.
pub(super) fn delete_room_host_pin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    HOST_PINS.delete(store, txn, &room)?;
    Ok(())
}

impl Memory<'_> {
    /// Refuses a room the caller's credential cannot read, or one outside
    /// the room turn it acts in.
    fn require_host_room(&self, room: EntityId) -> MemoryResult<()> {
        if self.room_turn().is_some_and(|turn| turn.room != room)
            || !self.room_record_readable(room)?
        {
            return Err(MemoryError::from(invalid()));
        }
        Ok(())
    }

    /// `session`'s live participants, earliest arrival first; none without
    /// a session.
    fn live_participants(&self, session: Option<EntityId>) -> MemoryResult<Vec<EntityId>> {
        Ok(match session {
            Some(session) => {
                self.vault()
                    .session_presence(session)?
                    .active_participant_ids
            }
            None => Vec::new(),
        })
    }

    /// Who hosts `room` now, and the caller's own speaking role there. The
    /// present set is `session`'s live participants in arrival order, then
    /// the caller; an absent leader is never assumed present. Only a caller
    /// standing in the room reads it, and reading it grants nothing.
    pub fn rooms_host(
        &self,
        room: EntityId,
        session: Option<EntityId>,
    ) -> MemoryResult<RoomStanding> {
        self.require_host_room(room)?;
        let mut present = self.live_participants(session)?;
        present.push(self.actor());
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        if !stands_in(self.vault(), &txn, room, self.actor())? {
            return Err(MemoryError::from(invalid()));
        }
        Ok(standing_in(
            self.vault(),
            &txn,
            room,
            self.actor(),
            &present,
        )?)
    }

    /// Pins `agent` as `room`'s host, or with none clears the room's stored
    /// host, pin or handoff; returns the caller's standing after. The caller
    /// passes the room's grant: its owner, or a delegate holding its delegate
    /// action, the party that admits to the room (OF-531). The agent must be
    /// one that may host ([`admit_room_host_in`]). A pin grants it no scope,
    /// room role, admission or turn.
    pub fn rooms_host_pin(&self, pin: &RoomHostPin) -> MemoryResult<RoomStanding> {
        self.require_host_room(pin.room)?;
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        let standing = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            if caller.actor_class() != EdgeActorClass::Human
                || room_host_in_txn(vault, txn, pin.room, caller)?.is_none()
            {
                return Err(MemoryError::from(lacks(
                    "only the room's owner or a delegated host pins its host",
                )));
            }
            match pin.agent {
                Some(agent) => {
                    admit_room_host_in(vault, txn, pin.room, agent)?;
                    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
                    HOST_PINS.put(
                        &vault.store,
                        txn,
                        &pin.room,
                        &HostPin {
                            agent,
                            by: caller.entity_ref(),
                            kind: HostPinKind::Pinned,
                            at,
                        },
                    )?;
                }
                None => {
                    HOST_PINS.delete(&vault.store, txn, &pin.room)?;
                }
            }
            Ok(standing_in(
                vault,
                txn,
                pin.room,
                caller.entity_ref(),
                &[caller.entity_ref()],
            )?)
        })?;
        // FIX 1794: the pin, or its clear, reaches the room's live window.
        #[cfg(feature = "sync")]
        vault.refresh_room_cell_in_live_window(pin.room, None);
        Ok(standing)
    }

    /// The room's current host hands the duty to `to`, another agent that
    /// may host, and returns the caller's standing after. The caller must
    /// hold the duty now as [`room_host_in`] reads it: by the stored pin or
    /// handoff, or by presence among `session`'s live participants, which
    /// must name it. A caller no session counts present hands nothing on.
    /// Stored as a handoff by the caller, latest write wins; it grants `to`
    /// no scope, room role, admission or turn.
    pub fn rooms_host_hand(&self, hand: &RoomHostHand) -> MemoryResult<RoomStanding> {
        self.require_host_room(hand.room)?;
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        if hand.to == caller.entity_ref() {
            return Err(MemoryError::from(lacks(
                "a host hands its duty to another agent",
            )));
        }
        let live = self.live_participants(hand.session)?;
        let mut present = live.clone();
        present.push(caller.entity_ref());
        let standing = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let hosting = room_host_in(vault, txn, hand.room, &present)?;
            if hosting.host != Some(caller.entity_ref())
                || (hosting.pin.is_none() && !live.contains(&caller.entity_ref()))
            {
                return Err(MemoryError::from(lacks(
                    "only the room's current host hands its host duty on",
                )));
            }
            admit_room_host_in(vault, txn, hand.room, hand.to)?;
            let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            HOST_PINS.put(
                &vault.store,
                txn,
                &hand.room,
                &HostPin {
                    agent: hand.to,
                    by: caller.entity_ref(),
                    kind: HostPinKind::HandedOff,
                    at,
                },
            )?;
            Ok(standing_in(
                vault,
                txn,
                hand.room,
                caller.entity_ref(),
                &present,
            )?)
        })?;
        // FIX 1794: the handoff reaches the room's live window.
        #[cfg(feature = "sync")]
        vault.refresh_room_cell_in_live_window(hand.room, None);
        Ok(standing)
    }
}
