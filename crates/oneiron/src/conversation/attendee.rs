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
//!
//! The owner answers P5 on a private surface: [`Vault::confirm_container_attendee`]
//! clears the entry's contact standing under a frozen offer and sets the
//! history it sees, [`Vault::deny_container_attendee`] refuses, and either
//! decides the entry once. The clearance stays the contact's own row; the
//! container adds no `(room, contact)` grant. A contact already cleared is
//! not asked or cleared again.

use serde::{Deserialize, Serialize};

use super::membership::HistoryChoice;
use super::*;
use crate::consent::{AuthenticatedOwner, ContactDisclosureOutcome, DisclosureConfirmationReceipt};
use crate::disclosure::{
    AttendeeIdentityChoice, DisclosureScopeStatus, RoomParty, UnknownAttendeeAsk,
};
use crate::error::GateError;
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::{AttendeeEntryFact, TaskAskReceipt};

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
    /// How much of the room's past a first-entering PERSON sees until the
    /// owner's P5 answer moves it; a speaker sees from its entry.
    pub history: HistoryChoice,
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
    /// Who the owner said an unplaced speaker is, on the entry revision;
    /// `None` while unanswered (unknown, so public-only) and for a PERSON.
    pub identity: Option<AttendeeIdentityChoice>,
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

/// Whether `person`, among the initial members of a room `creator` creates
/// with `body`, enters it for the first time (OF-365 P5) as a PERSON the
/// membership door joins does: anyone but the creator, the vault owner or
/// one of the vault's own agents. A project room keeps its own rule, and a
/// project-leader chat opens without an ask. The fact is the entry; the
/// create's join keeps its own time and history.
pub(super) fn initial_member_enters_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &crate::authority::AuthorityFold,
    body: &ConversationBody,
    creator: EntityId,
    person: EntityId,
) -> Result<bool> {
    if person == creator
        || body.extra.contains_key("project_id")
        || body.extra.contains_key("memberIds")
        || body
            .extra
            .contains_key(crate::workspace_roster::LEADER_CHAT_FIELD)
    {
        return Ok(false);
    }
    Ok(!matches!(
        crate::disclosure::room_party_in(vault, txn, fold, person)?,
        RoomParty::VaultOwner | RoomParty::VaultAgent
    ))
}

impl Memory<'_> {
    /// Records one attendee's entry into a container, and raises what P5
    /// asks of it, once.
    ///
    /// A PERSON the room's ledger has never held joins now, with the
    /// event's history (the room's rule unless the inviter chose); one it
    /// has held is rejoining, and nothing is recorded or asked. A speaker the vault cannot place gets its entry fact, which is
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
                    event.history,
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

    /// Records the entry of each speaker `roster` could not place into
    /// `container`, the committed room its voice session is heard in, through
    /// [`Self::container_attendee_entered`]: a
    /// [`ContainerAttendee::Speaker`] by the session's ref and the capture's
    /// speaker key, under the roster's revision, the keys the interlocutor
    /// read asks the identity at. A voice host that binds its session to a
    /// room calls it once the matcher has written the roster; `trigger_turn`,
    /// `candidates` (live contacts, in its order) and `until` are its own.
    /// A speaker already entered replays its stored entry. Answers each
    /// "who is this?" ask raised.
    pub fn voice_speakers_entered(
        &self,
        container: EntityId,
        roster: &crate::voice_identity::VoiceSessionRosterV1,
        trigger_turn: Option<EntityId>,
        candidates: &[EntityId],
        until: u64,
    ) -> MemoryResult<Vec<TaskAskReceipt>> {
        let mut asks = Vec::new();
        for speaker_key in roster.unplaced_speakers() {
            asks.extend(self.container_attendee_entered(&ContainerAttendeeEvent {
                container,
                attendee: ContainerAttendee::Speaker {
                    session_key: roster.voice_session_ref.clone(),
                    speaker_key: speaker_key.to_owned(),
                },
                roster_revision: roster.roster_revision,
                trigger_turn,
                candidates: candidates.to_vec(),
                until,
                history: HistoryChoice::Inherit,
            })?);
        }
        Ok(asks)
    }
}

fn not_clearable(reason: &'static str) -> Error {
    Error::Gate(GateError::InvalidConsentBound(reason))
}

impl Vault {
    /// The owner's yes to one entry's P5 question, in one write transaction:
    /// clears the contact this entry is, standing, under the frozen offer
    /// `proposal_ref` (exactly `expected_delta`), sets the history the entry
    /// sees, and takes the entry's decision slot so it is decided once.
    ///
    /// The offer must be for the entry's contact: a PERSON's room party, or
    /// the identity the owner gave an unplaced speaker on its entry
    /// revision. A contact already cleared gets no new standing clearance:
    /// its row already covers the entry, which keeps its history cut. An
    /// unplaced speaker is no member, so it sees from its entry; only a
    /// PERSON's history moves. Owner, offer, contact and prior clearance are
    /// all revalidated by the confirm door this runs.
    pub fn confirm_container_attendee(
        &self,
        owner: &AuthenticatedOwner,
        entry_ref: &EntityId,
        proposal_ref: &str,
        expected_delta: &[u8],
        history: HistoryChoice,
    ) -> Result<DisclosureConfirmationReceipt> {
        self.with_write_txn_grouped(|txn| {
            let (fact, contact) = self.entry_contact_in_txn(txn, entry_ref, proposal_ref)?;
            if crate::disclosure::contact_clearance_in_txn(&self.store, txn, &contact)?
                .is_some_and(|clearance| clearance.status == DisclosureScopeStatus::Active)
            {
                return Err(not_clearable(
                    "this contact is already cleared; its standing clearance covers the entry",
                ));
            }
            let receipt = self.confirm_contact_disclosure_in_txn(
                txn,
                owner,
                proposal_ref,
                expected_delta,
                ContactDisclosureOutcome::Standing,
            )?;
            self.take_decision_slot_in_txn(txn, &entry_slot(entry_ref), receipt.decision_id)?;
            self.entry_history_in_txn(txn, owner, &fact, history)?;
            Ok(receipt)
        })
    }

    /// The owner's no to one entry's P5 question: settles the frozen offer
    /// as denied, widens nothing, and decides the entry once. The entry
    /// keeps its history cut, and the contact its current clearance.
    pub fn deny_container_attendee(
        &self,
        owner: &AuthenticatedOwner,
        entry_ref: &EntityId,
        proposal_ref: &str,
        expected_delta: &[u8],
    ) -> Result<DisclosureConfirmationReceipt> {
        self.with_write_txn_grouped(|txn| {
            self.entry_contact_in_txn(txn, entry_ref, proposal_ref)?;
            let receipt = self.confirm_contact_disclosure_in_txn(
                txn,
                owner,
                proposal_ref,
                expected_delta,
                ContactDisclosureOutcome::Deny,
            )?;
            self.take_decision_slot_in_txn(txn, &entry_slot(entry_ref), receipt.decision_id)?;
            Ok(receipt)
        })
    }

    /// The entry `entry_ref` and the contact it is, bound to the offer
    /// `proposal_ref`: the offer must be about that contact.
    fn entry_contact_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entry_ref: &EntityId,
        proposal_ref: &str,
    ) -> Result<(AttendeeEntryFact, EntityId)> {
        let fact = crate::task_verb::read_attendee_entry_in(self, txn, *entry_ref)?
            .ok_or(Error::EntityNotFound)?;
        let contact = match &fact.attendee {
            ContainerAttendee::Person(person) => {
                let fold = self.authority_view_readonly_in_txn(txn)?;
                match crate::disclosure::room_party_in(self, txn, &fold, *person)? {
                    RoomParty::Contact(contact) => Some(contact),
                    _ => None,
                }
            }
            ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            } => match self.attendee_identity_in_txn(
                txn,
                session_key,
                speaker_key,
                fact.roster_revision,
            )? {
                Some(AttendeeIdentityChoice::Contact(contact)) => Some(contact),
                _ => None,
            },
        }
        .ok_or_else(|| not_clearable("this entry is no contact the owner can clear"))?;
        let offer = self
            .contact_disclosure_offer_in_txn(txn, proposal_ref)?
            .ok_or_else(|| not_clearable("no contact-disclosure offer is filed under this ref"))?;
        if offer.offer.contact_ref != contact {
            return Err(not_clearable("the offer is for another contact"));
        }
        Ok((fact, contact))
    }

    /// Applies the owner's history choice to the entry `fact`. A PERSON's
    /// current membership window starts at its join or at the origin; an
    /// unplaced speaker's cut is its entry and does not move.
    fn entry_history_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        fact: &AttendeeEntryFact,
        history: HistoryChoice,
    ) -> Result<()> {
        let shares = match history {
            HistoryChoice::Share => true,
            HistoryChoice::None => false,
            HistoryChoice::Inherit => body::body_in(self, txn, fact.container)?.shares_history(),
        };
        let ContainerAttendee::Person(person) = fact.attendee else {
            if shares {
                return Err(state("an unplaced speaker sees from its entry"));
            }
            return Ok(());
        };
        let window = self
            .windows_in_txn(txn, fact.container, person)?
            .pop()
            .filter(|window| window.to.is_none())
            .ok_or_else(|| state("not a current member"))?;
        let from = if shares { 0 } else { window.joined_at };
        if from == window.from {
            return Ok(());
        }
        let actor = WriteActor::new(
            owner.revalidate_in_txn(self, txn)?,
            crate::EdgeActorClass::Human,
        );
        let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        self.set_history_visibility_in_txn(txn, fact.container, person, actor, at, from)
    }

    /// The first entry of `attendee` into `container`; `None` until it
    /// entered.
    pub fn container_attendee_entry(
        &self,
        container: EntityId,
        attendee: &ContainerAttendee,
    ) -> Result<Option<ContainerAttendeeEntry>> {
        let txn = self.store.env.read_txn()?;
        self.container_attendee_entry_in_txn(&txn, container, attendee)
    }

    /// The entry `entry_ref` names; `None` for any other row. A host that
    /// was woken by a committed TASK reads the entry here.
    pub fn container_attendee_entry_by_ref(
        &self,
        entry_ref: EntityId,
    ) -> Result<Option<ContainerAttendeeEntry>> {
        let txn = self.store.env.read_txn()?;
        self.attendee_entry_in_txn(&txn, entry_ref)
    }

    /// [`Self::container_attendee_entry`] in the caller's snapshot.
    pub(crate) fn container_attendee_entry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        container: EntityId,
        attendee: &ContainerAttendee,
    ) -> Result<Option<ContainerAttendeeEntry>> {
        let entry_ref = crate::task_verb::attendee_entry_id(container, attendee)?;
        self.attendee_entry_in_txn(txn, entry_ref)
    }

    /// The entry `entry_ref` names, with the identity the owner gave an
    /// unplaced speaker on the revision it entered under.
    fn attendee_entry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entry_ref: EntityId,
    ) -> Result<Option<ContainerAttendeeEntry>> {
        let Some(fact) = crate::task_verb::read_attendee_entry_in(self, txn, entry_ref)? else {
            return Ok(None);
        };
        let identity = match &fact.attendee {
            ContainerAttendee::Person(_) => None,
            ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            } => {
                self.attendee_identity_in_txn(txn, session_key, speaker_key, fact.roster_revision)?
            }
        };
        Ok(Some(ContainerAttendeeEntry {
            entry_ref,
            container: fact.container,
            attendee: fact.attendee,
            roster_revision: fact.roster_revision,
            entered_at: fact.entered_at,
            identity,
            decided: entry_decided_in(self, txn, &entry_ref)?,
        }))
    }
}
