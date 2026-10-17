//! The protected first-entry fact of one attendee in one container (OF-365,
//! ILDF2 P5).
//!
//! One immutable TASK fact per (container, attendee), never per roster
//! revision, asker or device: that is what lets P5 ask once. It freezes the
//! engine's entry time, which is the attendee's history cut, and the route of
//! an unplaced speaker's identity ask, so an interrupted entry is raised by
//! the next call rather than asked twice.

use super::*;
use crate::conversation::{ContainerAttendee, ContainerAttendeeEvent};
use crate::disclosure::{PREDICATE_DISCLOSURE_ATTENDEE_ASK, attendee_ask_ref};

pub(super) const ATTENDEE_ENTRY: &str = "tasks.attendee_entry";
const ENTRY_ID_DOMAIN: &[u8] = b"oneiron.tasks.attendee_entry.v1";
const MAX_ATTENDEE_KEY_BYTES: usize = 128;
const MAX_ATTENDEE_CANDIDATES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttendeeEntryFact {
    /// The conversation entered.
    pub(crate) container: EntityId,
    pub(crate) attendee: ContainerAttendee,
    /// The roster revision of the first entry; a speaker's identity ask is
    /// frozen on it.
    pub(crate) roster_revision: u64,
    pub(crate) trigger_turn: Option<EntityId>,
    pub(crate) candidates: Vec<EntityId>,
    /// When the identity ask lapses unanswered (engine seconds).
    pub(crate) until: u64,
    /// The identity ask's route: the ask group its asker admits it under on
    /// the node that recorded the entry. `None` for a PERSON.
    pub(crate) ask_group: Option<EntityId>,
    /// Engine time of the first entry: the attendee's history cut.
    pub(crate) entered_at: u64,
}

impl AttendeeEntryFact {
    pub(super) fn validate(&self) -> Result<()> {
        if self.entered_at == 0 || self.roster_revision == 0 {
            return Err(invalid());
        }
        match &self.attendee {
            ContainerAttendee::Person(_) => {
                if !self.candidates.is_empty() || self.ask_group.is_some() {
                    return Err(invalid());
                }
            }
            ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            } => {
                for key in [session_key, speaker_key] {
                    if key.trim().is_empty()
                        || key.trim() != key
                        || key.len() > MAX_ATTENDEE_KEY_BYTES
                    {
                        return Err(invalid());
                    }
                }
                let distinct: std::collections::BTreeSet<_> = self.candidates.iter().collect();
                if self.ask_group.is_none()
                    || self.candidates.len() > MAX_ATTENDEE_CANDIDATES
                    || distinct.len() != self.candidates.len()
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

/// What admitting one entry found.
pub(crate) struct AttendeeEntryAdmission {
    pub(crate) entry_ref: EntityId,
    /// The stored fact: this entry's, or the first one when it already stood.
    pub(crate) fact: AttendeeEntryFact,
    /// This call recorded the first entry.
    pub(crate) first: bool,
    /// The speaker's identity ask is this asker's to raise on this node and
    /// is not admitted yet: a first entry, or one an interrupted call left.
    pub(crate) ask_pending: bool,
}

/// The entry fact id of `attendee` in `container`.
pub(crate) fn attendee_entry_id(
    container: EntityId,
    attendee: &ContainerAttendee,
) -> Result<EntityId> {
    match attendee {
        ContainerAttendee::Person(person) => EntityId::derive(
            ENTRY_ID_DOMAIN,
            &[container.as_bytes(), b"person", person.as_bytes()],
        ),
        ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } => EntityId::derive(
            ENTRY_ID_DOMAIN,
            &[
                container.as_bytes(),
                b"speaker",
                session_key.as_bytes(),
                speaker_key.as_bytes(),
            ],
        ),
    }
}

/// The intent key `Memory::raise_unknown_attendee_ask` admits a speaker's
/// identity ask under.
fn identity_intent(session_key: &str, speaker_key: &str, revision: u64) -> Result<String> {
    Ok(format!(
        "{PREDICATE_DISCLOSURE_ATTENDEE_ASK}/{}",
        attendee_ask_ref(session_key, speaker_key, revision)?.to_hex()
    ))
}

/// Records `event` as its attendee's first entry into its container, once.
/// A later event for the same attendee replays the stored fact: its entry
/// time, revision, candidates and route stay the first entry's.
pub(crate) fn admit_attendee_entry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    asker: EntityId,
    event: &ContainerAttendeeEvent,
) -> Result<AttendeeEntryAdmission> {
    let entry_ref = attendee_entry_id(event.container, &event.attendee)?;
    let (fact, first) = match read::<AttendeeEntryFact>(vault, txn, entry_ref, ATTENDEE_ENTRY)? {
        Some(stored) => (stored, false),
        None => {
            let entered_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let ask_group = match &event.attendee {
                ContainerAttendee::Person(_) => None,
                ContainerAttendee::Speaker {
                    session_key,
                    speaker_key,
                } => Some(group_id(
                    vault,
                    txn,
                    asker,
                    &identity_intent(session_key, speaker_key, event.roster_revision)?,
                )?),
            };
            let fact = AttendeeEntryFact {
                container: event.container,
                attendee: event.attendee.clone(),
                roster_revision: event.roster_revision,
                trigger_turn: event.trigger_turn,
                candidates: event.candidates.clone(),
                until: event.until,
                ask_group,
                entered_at,
            };
            fact.validate()?;
            put(vault, txn, entry_ref, ATTENDEE_ENTRY, &fact, entered_at)?;
            // The newcomer barrier's first arm, before the commit: output
            // marked before this entry no longer goes out into its
            // container. Its commit moves the mark again; a rollback only
            // over-cancels.
            vault
                .store
                .container_output
                .entering(entry_ref, event.container);
            (fact, true)
        }
    };
    let ask_pending = match (&fact.attendee, fact.ask_group) {
        (
            ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            },
            Some(route),
        ) => {
            group_id(
                vault,
                txn,
                asker,
                &identity_intent(session_key, speaker_key, fact.roster_revision)?,
            )? == route
                && read_group(vault, txn, route)?.is_none()
        }
        _ => false,
    };
    Ok(AttendeeEntryAdmission {
        entry_ref,
        fact,
        first,
        ask_pending,
    })
}

/// The entry fact `id` names; `None` for any other row.
pub(crate) fn read_attendee_entry_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<AttendeeEntryFact>> {
    read(vault, txn, id, ATTENDEE_ENTRY)
}
