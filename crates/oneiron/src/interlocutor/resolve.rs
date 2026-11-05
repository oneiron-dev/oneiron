//! Native interlocutor resolution with an optional retained contact-scope line.

use super::{
    CounterpartyContactStatus, EntityId, Error, HashSet, Interlocutor, InterlocutorPartyInput,
    InterlocutorResolutionInput, InterlocutorSet, Result, VOICE_ROSTER_UNRESOLVED_LABEL, Vault,
};

use crate::write_envelope::claim_body::{ClaimBodyReadError, ClaimScopeReadMemory};

impl Vault {
    /// Resolves conversation party inputs into an `InterlocutorSet` per the
    /// pinned rules (design §4):
    ///
    /// 1. `owner_session` alone controls whether an Owner entry exists.
    /// 2. `ContactRef`: Active contact -> `KnownContact`; Revoked ->
    ///    `Unknown` (a revoked contact must not retain known-contact
    ///    standing); missing -> `Error::EntityNotFound` (a dangling explicit
    ///    ref is a caller bug — fail loudly).
    /// 3. `ChannelCounterparty`: index hit with Active status ->
    ///    `KnownContact`; Revoked or no record -> `Unknown` labeled with the
    ///    counterparty key. The same input resolves `Unknown` before
    ///    `create_counterparty_contact` and `KnownContact` after.
    /// 4. `UnknownLabel`: `claimed_owner` carried verbatim as a label-only
    ///    flag.
    /// 5. `voice_session_ref`: resolved through the VOX-02 roster and merged
    ///    into the NON-OWNER entries — enrolled contacts become
    ///    `KnownContact` with `EnrolledVoicePrint` evidence, an enrolled
    ///    owner-print match becomes an `Unknown` entry flagged
    ///    `owner_print_matched`, invite-eliminated attendees become their
    ///    contact entry, and residual clusters stay anonymous `Unknown`s.
    ///    A supplied reference that cannot be resolved (missing or corrupt
    ///    roster) yields exactly ONE `Unknown` entry: failure narrows
    ///    disclosure and can never leave the caller in owner-alone mode.
    /// 6. Two inputs resolving to the same contact collapse to one entry;
    ///    label collision between Unknowns is allowed (labels are display
    ///    data).
    pub fn resolve_interlocutors(
        &self,
        input: &InterlocutorResolutionInput,
    ) -> Result<InterlocutorSet> {
        let rtxn = self.store.env.read_txn()?;
        self.resolve_interlocutors_in(&rtxn, input, &|_| Ok(true), true, None, None)
            .map_err(ClaimBodyReadError::into_unbound_error)
    }

    /// [`Self::resolve_interlocutors`] for a voice session its host bound
    /// to `container`, the committed room it is heard in (OF-365 P5). An
    /// unplaced speaker answers to its first entry there: the identity the
    /// owner gave on the revision it entered under, and the entry fact as
    /// its [`Interlocutor::audience_ref`]. A speaker with no entry yet has
    /// neither, and stays an anonymous unknown that narrows to nothing.
    pub fn resolve_interlocutors_in_container(
        &self,
        input: &InterlocutorResolutionInput,
        container: EntityId,
    ) -> Result<InterlocutorSet> {
        let rtxn = self.store.env.read_txn()?;
        self.resolve_interlocutors_in(&rtxn, input, &|_| Ok(true), true, Some(container), None)
            .map_err(ClaimBodyReadError::into_unbound_error)
    }

    /// [`Self::resolve_interlocutors`] for a caller that reads as `read`, in
    /// one snapshot: a contact `read` cannot read resolves as a missing one
    /// does. An explicit ref to it is `Error::EntityNotFound`, and a channel
    /// pair that finds it stays the caller's own unknown label. Denial reads
    /// as absence, so no status, label or id tells them apart. A voice
    /// roster's segments carry no record scope of their own, so a roster
    /// resolves only when `read_rosters`, for the owner's own unnarrowed read
    /// (`ScopedRead::is_unnarrowed_owner`); any other caller gets the one
    /// unresolved entry a missing roster gives.
    pub fn resolve_interlocutors_under(
        &self,
        input: &InterlocutorResolutionInput,
        read: &crate::claim::ScopedRead<'_>,
        read_rosters: bool,
        memory: Option<ClaimScopeReadMemory<'_>>,
    ) -> std::result::Result<InterlocutorSet, ClaimBodyReadError> {
        read.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        let policy = read.live_policy_manifest_in(&rtxn)?;
        self.resolve_interlocutors_in(
            &rtxn,
            input,
            &|id| read.is_ref_readable_with_policy_in(&rtxn, &policy, id),
            read_rosters,
            None,
            memory,
        )
    }

    /// [`Self::resolve_interlocutors_under`] for a read of `room`, a room
    /// the caller has proved it reads (FIX 1388 C1): a voice roster's
    /// speakers are read through their entries there, as a voice session
    /// bound to the room reads them.
    pub fn resolve_interlocutors_in_room_under(
        &self,
        input: &InterlocutorResolutionInput,
        read: &crate::claim::ScopedRead<'_>,
        read_rosters: bool,
        room: EntityId,
        memory: Option<ClaimScopeReadMemory<'_>>,
    ) -> std::result::Result<InterlocutorSet, ClaimBodyReadError> {
        read.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        let policy = read.live_policy_manifest_in(&rtxn)?;
        self.resolve_interlocutors_in(
            &rtxn,
            input,
            &|id| read.is_ref_readable_with_policy_in(&rtxn, &policy, id),
            read_rosters,
            Some(room),
            memory,
        )
    }

    fn resolve_interlocutors_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        input: &InterlocutorResolutionInput,
        admit: &dyn Fn(&EntityId) -> Result<bool>,
        read_rosters: bool,
        container: Option<EntityId>,
        memory: Option<ClaimScopeReadMemory<'_>>,
    ) -> std::result::Result<InterlocutorSet, ClaimBodyReadError> {
        let mut non_owner: Vec<Interlocutor> = Vec::with_capacity(input.parties.len());
        let mut seen_contact_refs: HashSet<String> = HashSet::new();

        for party in &input.parties {
            let entry = match party {
                InterlocutorPartyInput::ContactRef(id) => {
                    if !admit(id)? {
                        return Err(Error::EntityNotFound.into());
                    }
                    let record = self
                        .get_counterparty_contact_with_memory_in_txn(rtxn, id, memory)?
                        .ok_or(Error::EntityNotFound)?;
                    match record.status {
                        CounterpartyContactStatus::Active => self.known_contact_interlocutor(
                            *id,
                            &record.counterparty,
                            record.first_touch,
                        )?,
                        CounterpartyContactStatus::Revoked => {
                            Interlocutor::unknown(record.counterparty, false)
                        }
                    }
                }
                InterlocutorPartyInput::ChannelCounterparty {
                    identity_ref,
                    counterparty,
                } => {
                    match self.find_counterparty_contact_in_txn(rtxn, identity_ref, counterparty)? {
                        Some((id, record))
                            if record.status == CounterpartyContactStatus::Active
                                && admit(&id)? =>
                        {
                            self.known_contact_interlocutor(
                                id,
                                &record.counterparty,
                                record.first_touch,
                            )?
                        }
                        // FIX 9142 (L02 YES 12:33, reshaped per #4502 blind
                        // P1s rounds 1+2 REVIEW-4502.md): Active-but-unadmitted
                        // keeps an Unknown in the set so disclosure
                        // enforcement still counts the party, stamped with the
                        // caller-supplied counterparty fallback exactly like
                        // the no-record and Revoked arms below, so the three
                        // cases are observationally identical. No member hex
                        // is echoed.
                        Some((_, record)) if record.status == CounterpartyContactStatus::Active => {
                            Interlocutor::unknown(counterparty.clone(), false)
                        }
                        _ => Interlocutor::unknown(counterparty.clone(), false),
                    }
                }
                InterlocutorPartyInput::UnknownLabel {
                    label,
                    claimed_owner,
                } => Interlocutor::unknown(label.clone(), *claimed_owner),
            };

            if let Some(contact_ref) = entry.contact_ref.as_ref()
                && !seen_contact_refs.insert(contact_ref.clone())
            {
                continue;
            }
            non_owner.push(entry);
        }

        // ILD-3 (ONE-1800): merge the voice roster AFTER the party loop and
        // BEFORE the owner branch, so an Owner entry can still only come from
        // `session_owner()` via `with_session_owner`.
        if let Some(voice_session_ref) = input.voice_session_ref.as_deref() {
            let parties = if read_rosters {
                self.voice_roster_parties(rtxn, voice_session_ref, container)
            } else {
                Err(Error::EntityNotFound)
            };
            match parties {
                Ok(parties) => {
                    for entry in parties {
                        // A party read through an entry keeps its own cut,
                        // beside any other for the same contact.
                        if entry.audience_ref.is_none()
                            && let Some(contact_ref) = entry.contact_ref.as_ref()
                            && !seen_contact_refs.insert(contact_ref.clone())
                        {
                            continue;
                        }
                        non_owner.push(entry);
                    }
                }
                // Fail closed: one unknown participant, never "owner alone".
                Err(_) => {
                    non_owner.push(Interlocutor::unknown(VOICE_ROSTER_UNRESOLVED_LABEL, false));
                }
            }
        }

        Ok(if input.owner_session {
            InterlocutorSet::with_session_owner(non_owner)
        } else {
            InterlocutorSet::without_owner(non_owner)
        })
    }
}
