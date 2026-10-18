//! The live speakers of a room (FIX 1388/1389 C1/C2): the one engine source
//! of which voice calls are live in a room, and through them which speaker
//! entries its audience holds.
//!
//! A voice host registers its call here once its room proof is done and
//! holds the returned [`LiveSpeakerCall`] for the call's life; dropping it
//! ends the registration, whichever way the call ended. The index holds only
//! the room, the host's call token and the roster ref the call was heard
//! under. Everything else is re-read from durable state on every read: the
//! stored roster, the room's members and each speaker's entry fact. So a
//! read is its own refresh, and an entry the host has not recorded yet holds
//! the read with a typed [`RoomLiveSpeakersHold`] naming the call, never an
//! audience without it.
//!
//! Per vault, in memory, never persisted: a restart starts it empty and
//! hosts register again. An entry ref restricts a read as an audience term;
//! it is never a PERSON, a membership or a grant.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::*;
use crate::error::RoomLiveSpeakersHold;
use crate::interlocutor::{Interlocutor, InterlocutorSet};
use crate::voice_identity::{VoiceAttributionEvidence, VoiceSessionRosterV1};

/// Whether a live call with no stored roster holds its room's reads. While
/// nothing in production writes a roster (FIX 3344), it does not: the call
/// reads as one unresolved unknown beside the members, as it did before the
/// live source (CALLS "FIX 1388/1389 C2", amended 10-18).
const MISSING_ROSTER_HOLDS: bool = false;

/// The vault's live room-bound voice calls, by room.
#[derive(Debug, Default)]
pub(crate) struct LiveSpeakers {
    rooms: Mutex<BTreeMap<EntityId, LiveRoom>>,
}

#[derive(Debug, Default)]
struct LiveRoom {
    /// Moves on each register and end. A room keeps it after its last call
    /// ends, so a later call never reads as an earlier one did.
    revision: u64,
    /// Each live call's token and the roster ref its host heard it under.
    calls: BTreeMap<EntityId, Option<String>>,
}

impl LiveSpeakers {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<EntityId, LiveRoom>> {
        self.rooms.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, room: EntityId, call: EntityId, roster_ref: Option<String>) {
        let mut rooms = self.lock();
        let live = rooms.entry(room).or_default();
        live.revision = live.revision.saturating_add(1);
        live.calls.insert(call, roster_ref);
    }

    /// Token-exact and idempotent: an ended call never removes another.
    fn remove(&self, room: EntityId, call: EntityId) {
        let mut rooms = self.lock();
        if let Some(live) = rooms.get_mut(&room)
            && live.calls.remove(&call).is_some()
        {
            live.revision = live.revision.saturating_add(1);
        }
    }

    fn snapshot(&self, room: EntityId) -> (u64, Vec<(EntityId, Option<String>)>) {
        self.lock().get(&room).map_or((0, Vec::new()), |live| {
            (
                live.revision,
                live.calls
                    .iter()
                    .map(|(call, roster)| (*call, roster.clone()))
                    .collect(),
            )
        })
    }
}

/// One voice call live in a room, registered by its host after the room
/// proof. Hold it for the call's life: dropping it ends the registration,
/// on a normal end, a disconnect, a revoked credential, a shutdown or a
/// setup error alike.
#[must_use = "dropping the call ends its registration"]
pub struct LiveSpeakerCall {
    vault: Arc<Vault>,
    room: EntityId,
    call: EntityId,
}

impl LiveSpeakerCall {
    /// The host-minted token that names this call in a hold.
    #[must_use]
    pub fn call(&self) -> EntityId {
        self.call
    }

    #[must_use]
    pub fn room(&self) -> EntityId {
        self.room
    }
}

impl std::fmt::Debug for LiveSpeakerCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveSpeakerCall")
            .field("room", &self.room)
            .field("call", &self.call)
            .finish_non_exhaustive()
    }
}

impl Drop for LiveSpeakerCall {
    fn drop(&mut self) {
        self.vault.store.live_speakers.remove(self.room, self.call);
    }
}

/// A room's live speakers, as one read found them: the entry fact of each
/// speaker a live call must place, read through, and whether a live call
/// has no stored roster. Engine assembly data, never a wire roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomLiveSpeakerEntries {
    room: EntityId,
    revision: u64,
    calls: usize,
    rosterless: bool,
    entries: Vec<EntityId>,
}

impl RoomLiveSpeakerEntries {
    fn none(room: EntityId, revision: u64) -> Self {
        Self {
            room,
            revision,
            calls: 0,
            rosterless: false,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn room(&self) -> EntityId {
        self.room
    }

    /// Moves when a call goes live in the room or ends.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn has_live_calls(&self) -> bool {
        self.calls > 0
    }

    /// Whether a live call brings a listener the room's members do not
    /// cover: a speaker it must place, or a call with no stored roster.
    /// Such a listener's clearance is an unknown's.
    #[must_use]
    pub fn reads_unknown(&self) -> bool {
        self.rosterless || !self.entries.is_empty()
    }

    /// The entry fact of each speaker a live call must place, sorted: the
    /// audience terms the room's reads meet beside its members.
    #[must_use]
    pub fn entry_refs(&self) -> &[EntityId] {
        &self.entries
    }

    /// `set` with the room's live speakers it does not name yet: each entry
    /// no party already reads through joins as an unknown read through it,
    /// and a live call with no stored roster adds the one unresolved unknown
    /// a missing roster reads as, unless the set already holds it. Labels
    /// stay generic, so nothing of a roster the caller cannot read shows.
    #[must_use]
    pub fn merged_into(&self, set: InterlocutorSet) -> InterlocutorSet {
        let named: Vec<EntityId> = set
            .non_owner()
            .filter_map(Interlocutor::audience_ref)
            .collect();
        let mut added: Vec<Interlocutor> = self
            .entries
            .iter()
            .filter(|entry| !named.contains(entry))
            .map(|entry| Interlocutor::live_room_speaker(*entry))
            .collect();
        if self.rosterless
            && !set
                .non_owner()
                .any(Interlocutor::is_unresolved_voice_roster)
        {
            added.push(Interlocutor::unresolved_voice_roster());
        }
        if added.is_empty() {
            return set;
        }
        let supervised = set.supervised();
        let mut parties: Vec<Interlocutor> = set.non_owner().cloned().collect();
        parties.extend(added);
        if supervised {
            InterlocutorSet::with_session_owner(parties)
        } else {
            InterlocutorSet::without_owner(parties)
        }
    }
}

/// One speaker a live call must place in its room: heard on its roster and
/// not positively a member.
pub(crate) struct RequiredSpeaker<'a> {
    pub(crate) speaker_key: &'a str,
    /// Placed by print or invite: it enters with no "who is this?" ask.
    pub(crate) placed: bool,
}

/// The speakers of `roster` that `members` do not cover, in the order first
/// heard: every speaker the roster could not place, and every placed one
/// whose placed identity is not a member on every segment that placed it.
/// A placement that matches no member, or matches only partly, is not one.
pub(crate) fn required_live_speakers<'a>(
    roster: &'a VoiceSessionRosterV1,
    members: &[EntityId],
) -> Vec<RequiredSpeaker<'a>> {
    let mut keys: Vec<&str> = Vec::new();
    for segment in &roster.segments {
        if !keys.contains(&segment.speaker_key.as_str()) {
            keys.push(segment.speaker_key.as_str());
        }
    }
    keys.into_iter()
        .filter_map(|speaker_key| {
            let placed: Vec<EntityId> = roster
                .segments
                .iter()
                .filter(|segment| segment.speaker_key == speaker_key)
                .filter_map(|segment| match &segment.evidence {
                    VoiceAttributionEvidence::EnrolledPrint { subject_ref, .. } => {
                        Some(*subject_ref)
                    }
                    VoiceAttributionEvidence::InviteElimination { attendee_ref } => {
                        Some(*attendee_ref)
                    }
                    VoiceAttributionEvidence::ResidualCluster { .. } => None,
                })
                .collect();
            if placed.is_empty() {
                return Some(RequiredSpeaker {
                    speaker_key,
                    placed: false,
                });
            }
            let covered = placed.iter().all(|identity| members.contains(identity));
            (!covered).then_some(RequiredSpeaker {
                speaker_key,
                placed: true,
            })
        })
        .collect()
}

fn hold(room: EntityId, call: EntityId) -> Error {
    Error::Record(RecordError::RoomLiveSpeakersIncomplete(Box::new(
        RoomLiveSpeakersHold { room, call },
    )))
}

impl Vault {
    /// Registers a voice call live in `room`, heard under `roster_ref`. Only
    /// a voice host calls it, once it has proved the caller reads the room;
    /// the call is live until the returned registration drops. Output
    /// marked before now no longer goes out into the room: the call may
    /// bring listeners whose entries no new TASK announces.
    pub fn register_live_speaker_call(
        self: &Arc<Self>,
        room: EntityId,
        roster_ref: Option<String>,
    ) -> LiveSpeakerCall {
        let call = EntityId::now();
        self.store.live_speakers.register(room, call, roster_ref);
        self.store.container_output.changed(room);
        LiveSpeakerCall {
            vault: Arc::clone(self),
            room,
            call,
        }
    }

    /// `room`'s members as `read` reads them, with its live speakers, in one
    /// snapshot. A room `read` cannot read is a missing room, unless
    /// `member` is one of its members, as for
    /// [`Self::room_audience_members_under`]. A live call that is
    /// incomplete holds the read, typed.
    pub fn room_audience_with_live_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        room: EntityId,
        member: Option<EntityId>,
    ) -> Result<(Vec<EntityId>, RoomLiveSpeakerEntries)> {
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&txn)?;
        let members = if read.is_ref_readable_with_policy_in(&txn, &policy, &room)? {
            self.room_audience_members_in_txn(&txn, room)?
        } else {
            if !read.reaches_by_membership_in(&txn, &room)? {
                return Err(Error::EntityNotFound);
            }
            self.room_audience_members_in_txn(&txn, room)
                .ok()
                .filter(|members| member.is_some_and(|id| members.contains(&id)))
                .ok_or(Error::EntityNotFound)?
        };
        let live = self.live_speakers_for_members_in(&txn, room, &members)?;
        Ok((members, live))
    }

    /// `room`'s live speakers in the caller's snapshot, for a caller that
    /// has already proved it reads the room.
    pub(crate) fn room_live_speaker_entries_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
    ) -> Result<RoomLiveSpeakerEntries> {
        let (revision, calls) = self.store.live_speakers.snapshot(room);
        if calls.is_empty() {
            return Ok(RoomLiveSpeakerEntries::none(room, revision));
        }
        let members = self.room_audience_members_in_txn(txn, room)?;
        self.live_speakers_for_members_in(txn, room, &members)
    }

    /// Whether a voice call is live in `room` now, complete or not.
    pub(crate) fn room_has_live_call(&self, room: EntityId) -> bool {
        !self.store.live_speakers.snapshot(room).1.is_empty()
    }

    fn live_speakers_for_members_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        members: &[EntityId],
    ) -> Result<RoomLiveSpeakerEntries> {
        let (revision, calls) = self.store.live_speakers.snapshot(room);
        let mut live = RoomLiveSpeakerEntries::none(room, revision);
        live.calls = calls.len();
        for (call, roster_ref) in calls {
            let roster = match roster_ref.as_deref() {
                Some(roster_ref) => self.voice_session_roster_in_txn(txn, roster_ref)?,
                None => None,
            };
            let (Some(roster_ref), Some(roster)) = (roster_ref, roster) else {
                if MISSING_ROSTER_HOLDS {
                    return Err(hold(room, call));
                }
                live.rosterless = true;
                continue;
            };
            for speaker in required_live_speakers(&roster, members) {
                let entry = crate::task_verb::attendee_entry_id(
                    room,
                    &ContainerAttendee::Speaker {
                        session_key: roster_ref.clone(),
                        speaker_key: speaker.speaker_key.to_owned(),
                    },
                )?;
                if crate::task_verb::read_attendee_entry_in(self, txn, entry)?.is_none() {
                    return Err(hold(room, call));
                }
                live.entries.push(entry);
            }
        }
        live.entries.sort_unstable();
        live.entries.dedup();
        Ok(live)
    }
}
