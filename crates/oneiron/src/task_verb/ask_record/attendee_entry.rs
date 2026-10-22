//! The protected first-entry fact of one attendee in one container (OF-365,
//! ILDF2 P5).
//!
//! One immutable TASK fact per (container, attendee), never per roster
//! revision, asker or device: that is what lets P5 ask once. It freezes the
//! engine's entry time, which is the attendee's history cut, and the route of
//! an unplaced speaker's identity ask, so an interrupted entry is raised by
//! the next call rather than asked twice. A speaker entered with no ask, one
//! its roster placed or one in a project room, has no route.

use super::*;
use crate::conversation::{ContainerAttendee, ContainerAttendeeEvent};
use crate::disclosure::{PREDICATE_DISCLOSURE_ATTENDEE_ASK, attendee_ask_ref};

pub(super) const ATTENDEE_ENTRY: &str = "tasks.attendee_entry";
const ENTRY_ID_DOMAIN: &[u8] = b"oneiron.tasks.attendee_entry.v1";

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
    /// the node that recorded the entry. `None` for a PERSON, and for a
    /// speaker entered with no ask, which offers no candidates.
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
                // A key's length and the candidate count are observed where
                // the entry is admitted (FIX 10171), never refused here.
                for key in [session_key, speaker_key] {
                    if key.trim().is_empty() || key.trim() != key {
                        return Err(invalid());
                    }
                }
                let distinct: std::collections::BTreeSet<_> = self.candidates.iter().collect();
                if (self.ask_group.is_none() && !self.candidates.is_empty())
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

/// What a first entry asks.
#[derive(Clone, Copy)]
enum EntryAsk {
    /// A speaker's "who is this?", whose route the fact freezes.
    Identity,
    /// Nothing.
    Unasked,
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
    admit_in_txn(vault, txn, asker, event, EntryAsk::Identity)
}

/// [`admit_attendee_entry_in_txn`] with no identity ask: for a speaker its
/// roster placed, or one entering a project room. A first entry has no
/// route and no candidates, and none is ever pending. A stored entry
/// replays as it stands; an ask it once routed stays its own history.
pub(crate) fn admit_unasked_attendee_entry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    asker: EntityId,
    event: &ContainerAttendeeEvent,
) -> Result<AttendeeEntryAdmission> {
    admit_in_txn(vault, txn, asker, event, EntryAsk::Unasked)
}

fn admit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    asker: EntityId,
    event: &ContainerAttendeeEvent,
    ask: EntryAsk,
) -> Result<AttendeeEntryAdmission> {
    let entry_ref = attendee_entry_id(event.container, &event.attendee)?;
    let (fact, first) = match read::<AttendeeEntryFact>(vault, txn, entry_ref, ATTENDEE_ENTRY)? {
        Some(stored) => (stored, false),
        None => {
            let entered_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let ask_group = match (&event.attendee, ask) {
                (
                    ContainerAttendee::Speaker {
                        session_key,
                        speaker_key,
                    },
                    EntryAsk::Identity,
                ) => Some(group_id(
                    vault,
                    txn,
                    asker,
                    &identity_intent(session_key, speaker_key, event.roster_revision)?,
                )?),
                _ => None,
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
            observe_entry(vault, txn, entry_ref, &fact);
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
    let ask_pending = match (&fact.attendee, fact.ask_group, ask) {
        (
            ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            },
            Some(route),
            EntryAsk::Identity,
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

/// A first entry's candidate count and its longest key, each against its
/// scan row (FIX 10171): what the entry once refused past is observed, never
/// refused. A threshold row that does not read skips the observation, never
/// the entry; the crossing waits for the vault's next write of its own.
fn observe_entry(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entry_ref: EntityId,
    fact: &AttendeeEntryFact,
) {
    let longest_key = match &fact.attendee {
        ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } => session_key.len().max(speaker_key.len()),
        ContainerAttendee::Person(_) => 0,
    };
    for (scan, rows) in [
        (
            crate::scan_check::EngineScan::AttendeeIdentityCandidates,
            fact.candidates.len(),
        ),
        (
            crate::scan_check::EngineScan::AttendeeIdentityKeyBytes,
            longest_key,
        ),
    ] {
        if let Ok(mut count) =
            crate::scan_check::ScanCount::start(&vault.store, txn, scan, entry_ref.as_bytes())
        {
            count.rows(rows);
            count.defer(&vault.store);
        }
    }
}

impl crate::memory::Memory<'_> {
    /// Admits `spec`, the "who is this?" ask of an entry this call records,
    /// in `txn`, the entry's own writer (FIX 10172): the entry and its ask
    /// commit together, so no other asker or device is left a pending ask
    /// it cannot raise. The caller holds this surface's task-work turn and
    /// has verified its write on `txn`.
    pub(crate) fn compose_attendee_entry_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        spec: &crate::task_verb::TaskAskSpec,
    ) -> crate::memory::MemoryResult<crate::task_verb::TaskAskReceipt> {
        self.tasks_ask_composed_in_txn(txn, spec, None)
    }
}

/// The entry fact `id` names; `None` for any other row.
pub(crate) fn read_attendee_entry_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<AttendeeEntryFact>> {
    read(vault, txn, id, ATTENDEE_ENTRY)
}
