//! A placed attendee's first later identity question, separate from its
//! immutable first-entry history cut.

use super::*;
use crate::conversation::{ContainerAttendee, ContainerAttendeeEvent};
use crate::disclosure::UnknownAttendeeAsk;

pub(super) const ATTENDEE_LATE_ASK: &str = "tasks.attendee_late_ask";
const LATE_ASK_ID_DOMAIN: &[u8] = b"oneiron.tasks.attendee_late_ask.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttendeeLateAskFact {
    pub(super) entry_ref: EntityId,
    pub(super) container: EntityId,
    pub(super) session_key: String,
    pub(super) speaker_key: String,
    pub(super) roster_revision: u64,
    pub(super) trigger_turn: Option<EntityId>,
    pub(super) candidates: Vec<EntityId>,
    pub(super) until: u64,
    pub(super) ask_group: EntityId,
    pub(super) first_late_at: u64,
}

impl AttendeeLateAskFact {
    pub(super) fn validate(&self) -> Result<()> {
        if self.first_late_at == 0 || self.roster_revision == 0 {
            return Err(invalid());
        }
        for key in [&self.session_key, &self.speaker_key] {
            if key.trim().is_empty() || key.trim() != key {
                return Err(invalid());
            }
        }
        let distinct: std::collections::BTreeSet<_> = self.candidates.iter().collect();
        let attendee = ContainerAttendee::Speaker {
            session_key: self.session_key.clone(),
            speaker_key: self.speaker_key.clone(),
        };
        if distinct.len() != self.candidates.len()
            || super::attendee_entry::attendee_entry_id(self.container, &attendee)?
                != self.entry_ref
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn question(&self) -> UnknownAttendeeAsk {
        UnknownAttendeeAsk {
            session_key: self.session_key.clone(),
            speaker_key: self.speaker_key.clone(),
            roster_revision: self.roster_revision,
            trigger_turn: self.trigger_turn,
            candidates: self.candidates.clone(),
            until: self.until,
        }
    }
}

pub(super) fn late_ask_id(entry_ref: EntityId) -> Result<EntityId> {
    EntityId::derive(LATE_ASK_ID_DOMAIN, &[entry_ref.as_bytes()])
}

impl Vault {
    /// Freezes the first late question of an entry that originally asked
    /// nothing. Only its original asker and node may raise the pending
    /// route; a later call never retargets it or changes the entry fact.
    pub(crate) fn admit_late_attendee_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        asker: EntityId,
        entry_ref: EntityId,
        event: &ContainerAttendeeEvent,
    ) -> Result<Option<UnknownAttendeeAsk>> {
        let ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } = &event.attendee
        else {
            return Ok(None);
        };
        let id = late_ask_id(entry_ref)?;
        let fact = match read::<AttendeeLateAskFact>(self, txn, id, ATTENDEE_LATE_ASK)? {
            Some(stored) => stored,
            None => {
                let first_late_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                let fact = AttendeeLateAskFact {
                    entry_ref,
                    container: event.container,
                    session_key: session_key.clone(),
                    speaker_key: speaker_key.clone(),
                    roster_revision: event.roster_revision,
                    trigger_turn: event.trigger_turn,
                    candidates: event.candidates.clone(),
                    until: event.until,
                    ask_group: group_id(
                        self,
                        txn,
                        asker,
                        &super::attendee_entry::identity_intent(
                            session_key,
                            speaker_key,
                            event.roster_revision,
                        )?,
                    )?,
                    first_late_at,
                };
                fact.validate()?;
                put(self, txn, id, ATTENDEE_LATE_ASK, &fact, first_late_at)?;
                super::attendee_entry::observe_identity_shape(
                    self,
                    txn,
                    id,
                    fact.candidates.len(),
                    fact.session_key.len().max(fact.speaker_key.len()),
                );
                fact
            }
        };
        let route = group_id(
            self,
            txn,
            asker,
            &super::attendee_entry::identity_intent(
                &fact.session_key,
                &fact.speaker_key,
                fact.roster_revision,
            )?,
        )?;
        if route != fact.ask_group || read_group(self, txn, fact.ask_group)?.is_some() {
            return Ok(None);
        }
        Ok(Some(fact.question()))
    }

    /// The identity the owner gave a first-entered speaker: the answer on
    /// its original entry revision, or the first late answer where the
    /// entry asked nothing. `None` while unanswered and for a PERSON.
    pub(crate) fn attendee_entry_identity_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fact: &AttendeeEntryFact,
    ) -> Result<Option<crate::disclosure::AttendeeIdentityChoice>> {
        let ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } = &fact.attendee
        else {
            return Ok(None);
        };
        if let Some(choice) =
            self.attendee_identity_in_txn(txn, session_key, speaker_key, fact.roster_revision)?
        {
            return Ok(Some(choice));
        }
        let entry_ref = super::attendee_entry::attendee_entry_id(fact.container, &fact.attendee)?;
        let Some(late) =
            read::<AttendeeLateAskFact>(self, txn, late_ask_id(entry_ref)?, ATTENDEE_LATE_ASK)?
        else {
            return Ok(None);
        };
        late.validate()?;
        if late.entry_ref != entry_ref
            || late.container != fact.container
            || late.session_key != *session_key
            || late.speaker_key != *speaker_key
        {
            return Ok(None);
        }
        self.attendee_identity_in_txn(
            txn,
            &late.session_key,
            &late.speaker_key,
            late.roster_revision,
        )
    }
}
