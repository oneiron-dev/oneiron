//! Room hosting: the speaking duty, kept apart from the engine's upkeep.
//!
//! The engine performs every room's mechanical upkeep and a host does the
//! speaking part. The host is the nearest leader present, any member may hold
//! it, and the Dreamer never hosts (ARCH-0067 §8). Nothing here is stored:
//! hosting is read from the room's audience, its projects' signed leaders and
//! who is present now. It grants no scope, no room role and no turn.
use super::*;
use crate::error::RecordError;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};

/// How a member speaks in a room. Engine upkeep holds neither role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoomSpeakingRole {
    /// Holds the room's speaking duty.
    Host,
    /// Speaks when addressed, or when its posture lets it chime in.
    Member,
}

/// Who holds a room's speaking duty now.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomHosting {
    /// The nearest present leader, when exactly one is that near.
    pub host: Option<EntityId>,
    /// Who may hold it: the nearest present leaders, or every present member
    /// when no leader is here. Canon picks none among several; nor does the
    /// engine.
    pub candidates: Vec<EntityId>,
}

/// A member's reading of its room's hosting and of its own speaking role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomStanding {
    pub hosting: RoomHosting,
    /// `None` for an actor that speaks as no persona.
    pub role: Option<RoomSpeakingRole>,
}

fn refused() -> Error {
    Error::Record(RecordError::ConversationDenied)
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

/// The room's audience and, for a project home room, its project.
fn audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<(BTreeSet<EntityId>, Option<EntityId>)> {
    Ok(match project_room_of(vault, txn, room)? {
        Some(record) => (
            record
                .member_ids
                .iter()
                .map(|id| EntityId::from_hex(id))
                .collect::<Result<_>>()?,
            Some(EntityId::from_hex(&record.project_id)?),
        ),
        None => (vault.members_in_txn(txn, room)?.into_iter().collect(), None),
    })
}

/// Whether `actor` is a member of `room` who speaks as a persona.
fn persona_member_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    Ok(audience_in(vault, txn, room)?.0.contains(&actor)
        && eligible_room_speaker_in(vault, txn, actor)?)
}

/// The selection door every host passes: only a member who speaks as a
/// persona may hold `room`'s host duty. The Dreamer is refused here, typed,
/// as is any other upkeep actor or a non-member.
pub(crate) fn admit_room_host_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<()> {
    if !persona_member_in(vault, txn, room, actor)? {
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

/// Who hosts `room` among `present`, which the engine resolves and a request
/// never names. Present actors outside the room's audience, or speaking as no
/// persona, are left out. Leaders come from the signed project fold: the
/// room's own project first, then each ring of ancestors. The nearest ring
/// with a leader present decides; a tie names candidates and no host. With no
/// leader present, any present member may hold the duty.
pub(crate) fn room_host_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    present: &[EntityId],
) -> Result<RoomHosting> {
    let (audience, project) = audience_in(vault, txn, room)?;
    let mut here = BTreeSet::new();
    for actor in present {
        if audience.contains(actor) && eligible_room_speaker_in(vault, txn, *actor)? {
            here.insert(*actor);
        }
    }
    let mut seen: BTreeSet<EntityId> = project.into_iter().collect();
    let mut ring: Vec<EntityId> = seen.iter().copied().collect();
    while !ring.is_empty() {
        let mut leaders = BTreeSet::new();
        let mut next = Vec::new();
        for id in ring {
            let Some((_, effective)) = vault.effective_project_in_txn(txn, id)? else {
                continue;
            };
            let leader = EntityId::from_hex(&effective.leader)?;
            if here.contains(&leader) {
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
            let host = leaders.first().copied().filter(|_| leaders.len() == 1);
            if let Some(host) = host {
                admit_room_host_in(vault, txn, room, host)?;
            }
            return Ok(RoomHosting {
                host,
                candidates: leaders.into_iter().collect(),
            });
        }
        ring = next;
    }
    Ok(RoomHosting {
        host: None,
        candidates: here.into_iter().collect(),
    })
}

/// `actor`'s speaking role in `room` under `hosting`: Host for the selected
/// host, Member for any other member who speaks as a persona, and `None` for
/// upkeep or a non-member.
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

impl Memory<'_> {
    /// Who hosts `room` now, and the caller's own speaking role there. The
    /// present set is the caller and `session`'s live participants, met with
    /// the room's audience; an absent leader is never assumed present. Only a
    /// member reads it, and reading it grants nothing.
    pub fn rooms_host(
        &self,
        room: EntityId,
        session: Option<EntityId>,
    ) -> MemoryResult<RoomStanding> {
        if self.room_turn().is_some_and(|turn| turn.room != room)
            || !self.room_record_readable(room)?
        {
            return Err(MemoryError::from(invalid()));
        }
        let mut present = match session {
            Some(session) => {
                self.vault()
                    .session_presence(session)?
                    .active_participant_ids
            }
            None => Vec::new(),
        };
        present.push(self.actor());
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        if !audience_in(self.vault(), &txn, room)?
            .0
            .contains(&self.actor())
        {
            return Err(MemoryError::from(invalid()));
        }
        let hosting = room_host_in(self.vault(), &txn, room, &present)?;
        let role = room_speaking_role_in(self.vault(), &txn, room, self.actor(), &hosting)?;
        Ok(RoomStanding { hosting, role })
    }
}
