//! The handoff of an owner-named residual speaker into a PERSON membership
//! window (FIX 3634). A speaker the vault could not place entered a room as
//! an entry fact, its history cut, and the owner named it a contact on the
//! revision it entered under. The handoff joins the PERSON that contact is
//! as a member, under the membership authority a caller may already grant,
//! with no new approval step. Its proofs: the entry, the owner's identity
//! answer on it, and the contact's unique link to that PERSON.
//!
//! The new window's visible-from boundary is the caller's choice in the
//! act: the join time (the default, today's door) or the entry's cut, its
//! `entered_at`, which then carries into the window. The receipt records
//! which. The entry fact stays: it is the speaker's record, and its cut
//! still reads as it did.
//! Entry: `Vault::hand_off_speaker_entry`.

use serde::{Deserialize, Serialize};

use super::*;
use crate::disclosure::{AttendeeIdentityChoice, RoomParty};

/// Where a handed-off speaker's new PERSON window is visible from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerHandoffBoundary {
    /// From the join on: the membership door's own boundary.
    #[default]
    JoinTime,
    /// From the speaker's entry: the entry's cut carries into the window.
    EntryEnteredAt,
}

/// The handoff the caller asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeakerHandoff {
    /// The speaker's entry fact in its container.
    pub entry_ref: EntityId,
    /// The PERSON the owner's named contact is.
    pub person: EntityId,
    pub boundary: SpeakerHandoffBoundary,
    /// Who grants the membership: one the membership door admits today.
    pub actor: WriteActor,
}

/// What a handoff did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeakerHandoffReceipt {
    pub entry_ref: EntityId,
    pub container: EntityId,
    /// The contact the owner named the speaker.
    pub contact: EntityId,
    pub person: EntityId,
    /// The boundary the caller picked.
    pub boundary: SpeakerHandoffBoundary,
    /// When the PERSON's new window is visible from.
    pub visible_from: u64,
    /// When the PERSON joined.
    pub joined_at: u64,
}

impl Vault {
    /// Moves the owner-named residual speaker `request.entry_ref` names into
    /// a membership window of `request.person`, in one write transaction.
    /// Refused, typed, for an entry that is no speaker's, a speaker the owner
    /// named no contact on its entry revision, a PERSON that contact is not
    /// uniquely linked to, a PERSON already a member, or an actor the
    /// membership door does not admit.
    pub fn hand_off_speaker_entry(
        &self,
        request: &SpeakerHandoff,
    ) -> Result<SpeakerHandoffReceipt> {
        self.with_write_txn_grouped(|txn| {
            let fact = crate::task_verb::read_attendee_entry_in(self, txn, request.entry_ref)?
                .ok_or(Error::EntityNotFound)?;
            let ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            } = &fact.attendee
            else {
                return Err(state("only a speaker's entry is handed to a PERSON"));
            };
            let contact = match self.attendee_identity_in_txn(
                txn,
                session_key,
                speaker_key,
                fact.roster_revision,
            )? {
                Some(AttendeeIdentityChoice::Contact(contact)) => contact,
                _ => return Err(state("the owner named this speaker no contact")),
            };
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if crate::disclosure::bound_room_party_in(self, txn, &fold, request.person)?
                != RoomParty::Contact(contact)
            {
                return Err(state("the named contact is not this PERSON's one contact"));
            }
            let joined_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let visible_from = match request.boundary {
                SpeakerHandoffBoundary::JoinTime => joined_at,
                SpeakerHandoffBoundary::EntryEnteredAt => fact.entered_at.min(joined_at),
            };
            self.join_member_from_in_txn(
                txn,
                fact.container,
                request.person,
                request.actor,
                joined_at,
                visible_from,
            )?;
            Ok(SpeakerHandoffReceipt {
                entry_ref: request.entry_ref,
                container: fact.container,
                contact,
                person: request.person,
                boundary: request.boundary,
                visible_from,
                joined_at,
            })
        })
    }
}
