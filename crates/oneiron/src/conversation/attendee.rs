//! An attendee's first entry into a chat or room (OF-365, ILDF2 P5).
//!
//! P5 asks what a newcomer may see, and from when, once: the first time they
//! enter a container, never again on a rejoin, a new roster revision or
//! another device. One protected TASK fact per (container, attendee) records
//! that entry, and its own owner-decision slot marks the question decided;
//! the membership ledger tells a PERSON's first entry from a rejoin. The
//! default is from now: a first entry's history cut is the engine's entry
//! time, never a caller's clock. A project room keeps its own rule and asks
//! nothing.
//!
//! A speaker the vault cannot place yet is no room member. Its cut stays on
//! its entry fact and the audience predicate reads it there, so an unplaced
//! speaker is never dropped from an audience while it waits to be
//! identified. Its "who is this?" ask (ILDF2 P4) is raised once, on the
//! roster revision it first entered under.

use serde::{Deserialize, Serialize};

use super::membership::HistoryChoice;
use super::*;
use crate::disclosure::UnknownAttendeeAsk;
use crate::error::GateError;
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::TaskAskReceipt;

const ENTRY_SLOT_DOMAIN: &[u8] = b"oneiron.conversation.attendee_entry.slot.v1";

/// Who entered a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerAttendee {
    /// A PERSON entering as a room member.
    Person(EntityId),
    /// A speaker the vault cannot place yet, by its stable keys.
    Speaker {
        session_key: String,
        speaker_key: String,
    },
}

/// One attendee entering one container, as the host delivers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerAttendeeEvent {
    /// The conversation (chat, room or meeting) entered.
    pub container: EntityId,
    pub attendee: ContainerAttendee,
    /// The roster revision the attendee was seen under; nonzero.
    pub roster_revision: u64,
    /// The durable TURN the entry was heard in, when one exists.
    pub trigger_turn: Option<EntityId>,
    /// Live contacts an unplaced speaker may be, in the host's order; empty
    /// for a PERSON.
    pub candidates: Vec<EntityId>,
    /// When a "who is this?" ask lapses unanswered (engine seconds).
    pub until: u64,
}

/// The recorded first entry of one attendee into one container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerAttendeeEntry {
    /// The entry fact. An audience names it for an unplaced speaker.
    pub entry_ref: EntityId,
    pub container: EntityId,
    pub attendee: ContainerAttendee,
    /// The roster revision of the first entry.
    pub roster_revision: u64,
    /// Engine time of the first entry: the attendee's history cut.
    pub entered_at: u64,
    /// An owner decided this entry's P5 question.
    pub decided: bool,
}

/// The owner-decision slot of one entry's P5 question. The identity slot of
/// a speaker's "who is this?" answers one roster revision only; this one is
/// the entry's, so a decided entry is never asked again.
fn entry_slot(entry_ref: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENTRY_SLOT_DOMAIN);
    hasher.update(entry_ref.as_bytes());
    *hasher.finalize().as_bytes()
}

fn entry_decided_in(vault: &Vault, txn: &heed::RoTxn<'_>, entry_ref: &EntityId) -> Result<bool> {
    match vault.ensure_decision_slot_open_in_txn(txn, &entry_slot(entry_ref)) {
        Ok(()) => Ok(false),
        Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether the unplaced speaker whose entry fact `audience_ref` names may
/// see a record of `room` that occurred at `at`: it entered `room` by then.
/// A PERSON's window is the ledger's, and any other id admits nothing here.
pub(super) fn speaker_entry_covers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    audience_ref: EntityId,
    at: u64,
) -> Result<bool> {
    Ok(
        crate::task_verb::read_attendee_entry_in(vault, txn, audience_ref)?.is_some_and(|fact| {
            fact.container == room
                && matches!(fact.attendee, ContainerAttendee::Speaker { .. })
                && fact.entered_at <= at
        }),
    )
}

impl Memory<'_> {
    /// Records one attendee's entry into a container, and raises what P5
    /// asks of it, once.
    ///
    /// A PERSON the room's ledger has never held joins now, with history
    /// from now; one it has held is rejoining, and nothing is recorded or
    /// asked. A speaker the vault cannot place gets its entry fact, which is
    /// its history cut, and on its first entry only the owner's "who is
    /// this?" ask on the revision it entered under. A later revision, a
    /// rejoin or another device replays the stored entry and asks nothing;
    /// an entry whose ask an interrupted call never admitted is raised by the
    /// next call. A project room keeps its own rule.
    ///
    /// Returns the identity ask this call raised, if it raised one.
    pub fn container_attendee_entered(
        &self,
        event: &ContainerAttendeeEvent,
    ) -> MemoryResult<Option<TaskAskReceipt>> {
        let vault = self.vault();
        let writer = WriteActor::new(self.actor(), self.actor_class());
        let pending = self.with_verified_actor_write_txn(|txn| {
            body::body_in(vault, txn, event.container)?;
            if crate::workspace_roster::project_room_audience_in(vault, txn, event.container, &[])?
                .is_some()
            {
                return Ok(None);
            }
            if let ContainerAttendee::Person(person) = &event.attendee
                && vault
                    .ever_members_in_txn(txn, event.container)?
                    .contains(person)
            {
                return Ok(None);
            }
            let admitted =
                crate::task_verb::admit_attendee_entry_in_txn(vault, txn, self.actor(), event)?;
            if let ContainerAttendee::Person(person) = &admitted.fact.attendee
                && admitted.first
            {
                vault.join_member_in_txn(
                    txn,
                    event.container,
                    *person,
                    writer,
                    admitted.fact.entered_at,
                    HistoryChoice::None,
                )?;
            }
            let decided = entry_decided_in(vault, txn, &admitted.entry_ref)?;
            Ok((admitted.ask_pending && !decided).then_some(admitted.fact))
        })?;
        let Some(fact) = pending else {
            return Ok(None);
        };
        let ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } = fact.attendee
        else {
            return Ok(None);
        };
        // After the entry commits: the ask door opens its own writer, and a
        // failure here leaves the entry pending for the next call to raise.
        self.raise_unknown_attendee_ask(&UnknownAttendeeAsk {
            session_key,
            speaker_key,
            roster_revision: fact.roster_revision,
            trigger_turn: fact.trigger_turn,
            candidates: fact.candidates,
            until: fact.until,
        })
        .map(Some)
    }
}

impl Vault {
    /// The first entry of `attendee` into `container`; `None` until it
    /// entered.
    pub fn container_attendee_entry(
        &self,
        container: EntityId,
        attendee: &ContainerAttendee,
    ) -> Result<Option<ContainerAttendeeEntry>> {
        let entry_ref = crate::task_verb::attendee_entry_id(container, attendee)?;
        let txn = self.store.env.read_txn()?;
        let Some(fact) = crate::task_verb::read_attendee_entry_in(self, &txn, entry_ref)? else {
            return Ok(None);
        };
        Ok(Some(ContainerAttendeeEntry {
            entry_ref,
            container: fact.container,
            attendee: fact.attendee,
            roster_revision: fact.roster_revision,
            entered_at: fact.entered_at,
            decided: entry_decided_in(self, &txn, &entry_ref)?,
        }))
    }
}
