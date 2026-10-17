//! Interlocutor resolution substrate (OF-365 ILD-1).
//!
//! Resolves conversation participants into owner / known-contact / unknown
//! classes for disclosure clamping (ILD-2) and per-speaker
//! claims-not-instructions stamping. The constructor law is the security
//! core: no wire path and no public constructor can mint an `Owner`-class
//! entry with anything but `AuthenticatedSession` evidence, so supervised
//! disclosure keys to the session — never to a voice claim or message text.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::conversation::ContainerAttendee;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyContactStatus, CounterpartyFirstTouch,
};
use crate::disclosure::AttendeeIdentityChoice;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::voice_identity::{VoiceAttributionEvidence, VoiceResolvedSegment};

/// Display label for a supplied voice roster that could not be resolved. The
/// entry exists so an unresolvable roster narrows disclosure instead of
/// silently leaving the caller in owner-alone mode.
const VOICE_ROSTER_UNRESOLVED_LABEL: &str = "unresolved voice roster";

/// Who a conversation participant is, as the disclosure clamp sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InterlocutorClass {
    Owner,
    KnownContact,
    Unknown,
}

impl InterlocutorClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::KnownContact => "known_contact",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "known_contact" => Some(Self::KnownContact),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// OF-365 presence-evidence ladder (amendment 2026-07-07). Higher rank =
/// stronger evidence.
///
/// Deliberately carries no `Deserialize`: no wire-deserializable type may
/// carry `AuthenticatedSession` into the engine (design §14.5 item 8). The
/// wire DTOs cannot express evidence at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PresenceEvidence {
    AuthenticatedSession,
    EnrolledVoicePrint,
    FirstClaim,
}

impl PresenceEvidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedSession => "authenticated_session",
            Self::EnrolledVoicePrint => "enrolled_voice_print",
            Self::FirstClaim => "first_claim",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::AuthenticatedSession => 3,
            Self::EnrolledVoicePrint => 2,
            Self::FirstClaim => 1,
        }
    }
}

/// One resolved conversation participant.
///
/// Fields are private behind read accessors (design §3, ILD J2 ruling): the
/// only paths to an `Owner`-class value are the `InterlocutorSet` session
/// constructors, which makes the constructor law compile-enforced outside
/// this module. No `Deserialize` (design §14.5 item 8).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Interlocutor {
    class: InterlocutorClass,
    evidence: PresenceEvidence,
    label: String,
    contact_ref: Option<String>,
    first_touch: Option<CounterpartyFirstTouch>,
    relationship: Option<String>,
    claimed_owner: bool,
    owner_print_matched: bool,
    /// The entry fact of an unplaced voice speaker in the container its
    /// session is bound to (OF-365 P5): its history cut, which an audience
    /// names until the speaker is placed. Kept when the owner names the
    /// speaker, since a name alone is no membership window.
    #[serde(skip_serializing_if = "Option::is_none")]
    audience_ref: Option<EntityId>,
}

impl Interlocutor {
    /// Builds a known-contact entry from an Active CID-7 contact record.
    #[must_use]
    pub fn known_contact(
        contact_ref: EntityId,
        label: impl Into<String>,
        first_touch: CounterpartyFirstTouch,
    ) -> Self {
        Self {
            class: InterlocutorClass::KnownContact,
            evidence: PresenceEvidence::FirstClaim,
            label: label.into(),
            contact_ref: Some(contact_ref.to_hex()),
            first_touch: Some(first_touch),
            relationship: None,
            claimed_owner: false,
            owner_print_matched: false,
            audience_ref: None,
        }
    }

    /// Builds an unknown-party entry. A spoofed "it's me" arrives here as
    /// `claimed_owner: true` — a display label only, never authority.
    #[must_use]
    pub fn unknown(label: impl Into<String>, claimed_owner: bool) -> Self {
        Self {
            class: InterlocutorClass::Unknown,
            evidence: PresenceEvidence::FirstClaim,
            label: label.into(),
            contact_ref: None,
            first_touch: None,
            relationship: None,
            claimed_owner,
            owner_print_matched: false,
            audience_ref: None,
        }
    }

    /// An enrolled OWNER voice print matched without an authenticated
    /// session (ILD-3). Deliberately `Unknown` class: a voice match is
    /// corroboration for display, never supervision and never authority, so
    /// `owner_print_matched` is the only thing that distinguishes this entry.
    /// Private, like `session_owner`, so no caller outside this module can
    /// route around the class choice.
    fn voice_matched_owner(label: impl Into<String>) -> Self {
        Self {
            class: InterlocutorClass::Unknown,
            evidence: PresenceEvidence::EnrolledVoicePrint,
            label: label.into(),
            contact_ref: None,
            first_touch: None,
            relationship: None,
            claimed_owner: false,
            owner_print_matched: true,
            audience_ref: None,
        }
    }

    /// An enrolled CONTACT voice print matched against a CID-7 contact record
    /// (ILD-3): the same known-contact standing the text path grants, carrying
    /// the stronger enrolled-print evidence rung.
    fn voice_matched_contact(
        contact_ref: EntityId,
        label: impl Into<String>,
        first_touch: CounterpartyFirstTouch,
    ) -> Self {
        Self {
            class: InterlocutorClass::KnownContact,
            evidence: PresenceEvidence::EnrolledVoicePrint,
            label: label.into(),
            contact_ref: Some(contact_ref.to_hex()),
            first_touch: Some(first_touch),
            relationship: None,
            claimed_owner: false,
            owner_print_matched: false,
            audience_ref: None,
        }
    }

    /// The session-owner entry. Private: only the `InterlocutorSet`
    /// constructors may mint an `Owner`-class value, and they hardcode
    /// `AuthenticatedSession` evidence (invariant: `class == Owner` implies
    /// `evidence == AuthenticatedSession`).
    fn session_owner() -> Self {
        Self {
            class: InterlocutorClass::Owner,
            evidence: PresenceEvidence::AuthenticatedSession,
            label: "owner".to_owned(),
            contact_ref: None,
            first_touch: None,
            relationship: None,
            claimed_owner: false,
            owner_print_matched: false,
            audience_ref: None,
        }
    }

    #[must_use]
    pub fn class(&self) -> InterlocutorClass {
        self.class
    }

    #[must_use]
    pub fn evidence(&self) -> PresenceEvidence {
        self.evidence
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Hex CounterpartyContact entity id when the class is `KnownContact`.
    #[must_use]
    pub fn contact_ref(&self) -> Option<&str> {
        self.contact_ref.as_deref()
    }

    #[must_use]
    pub fn first_touch(&self) -> Option<CounterpartyFirstTouch> {
        self.first_touch
    }

    /// Opaque OF-331 relationship label when present (FED-05 owns the
    /// vocabulary; see `relationship_label_for_contact`).
    #[must_use]
    pub fn relationship(&self) -> Option<&str> {
        self.relationship.as_deref()
    }

    /// ASYMMETRY LAW: an owner claim is an attribution label, never authority.
    #[must_use]
    pub fn claimed_owner(&self) -> bool {
        self.claimed_owner
    }

    /// Enrolled-print corroboration display, never a sole authenticator.
    #[must_use]
    pub fn owner_print_matched(&self) -> bool {
        self.owner_print_matched
    }

    /// The entry fact an audience names for this party in place of a
    /// PERSON: set only for a speaker of a container-bound voice session
    /// that entered it unplaced. The record cut is the entry's.
    #[must_use]
    pub fn audience_ref(&self) -> Option<EntityId> {
        self.audience_ref
    }
}

/// The resolved participant set one context assembly is clamped against.
///
/// The `entries` field is private and the session constructors below are the
/// only paths that produce an `Owner` entry, which keeps `supervised()`
/// trustworthy. No `Deserialize` (design §14.5 item 8).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterlocutorSet {
    entries: Vec<Interlocutor>,
}

impl InterlocutorSet {
    /// The owner alone on an authenticated session — today's default.
    #[must_use]
    pub fn owner_alone() -> Self {
        Self {
            entries: vec![Interlocutor::session_owner()],
        }
    }

    /// The session owner plus non-owner participants.
    ///
    /// Any `Owner`-class entry in `non_owner` is FILTERED out (defense in
    /// depth): the only `Owner` entry a set may contain is the one this
    /// constructor mints. Filtering rather than erroring is fail-closed — a
    /// dropped forgery only narrows disclosure.
    #[must_use]
    pub fn with_session_owner(non_owner: Vec<Interlocutor>) -> Self {
        let mut entries = vec![Interlocutor::session_owner()];
        entries.extend(filter_owner_forgeries(non_owner));
        Self { entries }
    }

    /// An owner-less participant set. Applies the same owner-forgery filter
    /// as `with_session_owner`, so a forged literal can never flip
    /// `supervised()`.
    #[must_use]
    pub fn without_owner(non_owner: Vec<Interlocutor>) -> Self {
        Self {
            entries: filter_owner_forgeries(non_owner).collect(),
        }
    }

    /// Returns whether a session-owner entry is present.
    #[must_use]
    pub fn supervised(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.class == InterlocutorClass::Owner)
    }

    /// Iterates the non-owner entries in set order.
    pub fn non_owner(&self) -> impl Iterator<Item = &Interlocutor> {
        self.entries
            .iter()
            .filter(|entry| entry.class != InterlocutorClass::Owner)
    }

    #[must_use]
    pub fn has_non_owner(&self) -> bool {
        self.non_owner().next().is_some()
    }

    #[must_use]
    pub fn entries(&self) -> &[Interlocutor] {
        &self.entries
    }

    /// Whether `other` holds the same people, placed the same way: entry for
    /// entry, the same class, presence evidence, contact, owner flags and
    /// container entry. One unknown replacing another is no same audience,
    /// since each enters with a cut of its own. Labels, relationship names
    /// and first-touch notes are cosmetic and do not count.
    #[must_use]
    pub fn same_audience(&self, other: &Self) -> bool {
        type Placed<'a> = (
            &'static str,
            &'static str,
            Option<&'a str>,
            bool,
            bool,
            Option<EntityId>,
        );
        fn placed(set: &InterlocutorSet) -> Vec<Placed<'_>> {
            let mut placed: Vec<_> = set
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.class.as_str(),
                        entry.evidence.as_str(),
                        entry.contact_ref.as_deref(),
                        entry.claimed_owner,
                        entry.owner_print_matched,
                        entry.audience_ref,
                    )
                })
                .collect();
            placed.sort_unstable();
            placed
        }
        placed(self) == placed(other)
    }

    /// One per-speaker claims-not-instructions stamp per entry.
    #[must_use]
    pub fn stamps(&self) -> Vec<InterlocutorStamp> {
        self.entries
            .iter()
            .map(InterlocutorStamp::for_interlocutor)
            .collect()
    }
}

fn filter_owner_forgeries(non_owner: Vec<Interlocutor>) -> impl Iterator<Item = Interlocutor> {
    non_owner
        .into_iter()
        .filter(|entry| entry.class != InterlocutorClass::Owner)
}

/// Per-speaker claims-not-instructions stamp (CID-6 stamps the event, ILD-1
/// stamps the speaker).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterlocutorStamp {
    /// Contact entity hex id when known, else the display label or "owner".
    pub speaker: String,
    pub class: InterlocutorClass,
    /// INVARIANT: `class != Owner` implies `true` (constructor-enforced).
    pub claims_not_instructions: bool,
}

impl InterlocutorStamp {
    /// Sole constructor: derives the claims-not-instructions bit from the
    /// class so the canon rule is non-forgeable.
    #[must_use]
    pub fn for_interlocutor(entry: &Interlocutor) -> Self {
        Self {
            speaker: entry
                .contact_ref
                .clone()
                .unwrap_or_else(|| entry.label.clone()),
            class: entry.class,
            claims_not_instructions: entry.class != InterlocutorClass::Owner,
        }
    }
}

/// Validates an app-embedded interlocutor stamp value (D4 opt-in for callers
/// that embed stamps in turn bodies; the engine does not retro-type turn
/// bodies).
pub fn validate_interlocutor_stamp_value(value: &serde_json::Value) -> Result<()> {
    const STAMP_KEYS: [&str; 3] = ["speaker", "class", "claims_not_instructions"];

    let Some(map) = value.as_object() else {
        return Err(invalid_stamp("interlocutor stamp must be a JSON object"));
    };
    if map.len() != STAMP_KEYS.len() || !STAMP_KEYS.iter().all(|key| map.contains_key(*key)) {
        return Err(invalid_stamp(
            "interlocutor stamp must contain exactly speaker, class, claims_not_instructions",
        ));
    }
    let speaker = map
        .get("speaker")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_stamp("interlocutor stamp speaker must be a string"))?;
    if speaker.trim().is_empty() {
        return Err(invalid_stamp(
            "interlocutor stamp speaker must be non-empty",
        ));
    }
    let class = map
        .get("class")
        .and_then(serde_json::Value::as_str)
        .and_then(InterlocutorClass::parse)
        .ok_or_else(|| {
            invalid_stamp("interlocutor stamp class must be owner|known_contact|unknown")
        })?;
    let claims_not_instructions = map
        .get("claims_not_instructions")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            invalid_stamp("interlocutor stamp claims_not_instructions must be a boolean")
        })?;
    if claims_not_instructions != (class != InterlocutorClass::Owner) {
        return Err(invalid_stamp(
            "interlocutor stamp claims_not_instructions must be true for non-owner speakers",
        ));
    }
    Ok(())
}

fn invalid_stamp(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// One party input to interlocutor resolution. Never a wire type: the server
/// DTOs map into it and carry no way to express class or evidence.
#[derive(Debug, Clone, PartialEq)]
pub enum InterlocutorPartyInput {
    /// Explicit CID-7 contact reference (`SurfaceCounterpartyStamp::Known`).
    ContactRef(EntityId),
    /// CID-6 unknown stamp / text channels: resolved through the
    /// per-(identity, counterparty) contact index.
    ChannelCounterparty {
        identity_ref: EntityId,
        counterparty: String,
    },
    /// Voice / untyped parties.
    UnknownLabel { label: String, claimed_owner: bool },
}

/// Input to `Vault::resolve_interlocutors`.
#[derive(Debug, Clone, PartialEq)]
pub struct InterlocutorResolutionInput {
    /// Asserted by the EMBEDDER's auth layer (design §11), never by remote
    /// text.
    pub owner_session: bool,
    pub parties: Vec<InterlocutorPartyInput>,
    /// Voice-session roster reference; accepted from ILD-1, merged in ILD-3.
    pub voice_session_ref: Option<String>,
}

/// Single FED-05 wiring point for the OF-331 relationship label.
///
/// Seam rule (design §4): no `relationship.*` claim vocabulary exists at
/// main; the FED chain owns minting it. This adapter returns `None` until
/// FED-05 lands and MUST NOT mint any `relationship.*` predicate here.
/// The signature is pinned `Result` for the fallible vault read FED-05 wires.
#[expect(clippy::unnecessary_wraps)]
fn relationship_label_for_contact(
    _vault: &Vault,
    _contact_ref: &EntityId,
) -> Result<Option<String>> {
    Ok(None)
}

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
        self.resolve_interlocutors_in(&rtxn, input, &|_| Ok(true), true, None)
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
        self.resolve_interlocutors_in(&rtxn, input, &|_| Ok(true), true, Some(container))
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
    ) -> Result<InterlocutorSet> {
        read.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&rtxn)?;
        self.resolve_interlocutors_in(
            &rtxn,
            input,
            &|id| read.is_ref_readable_with_policy_in(&rtxn, &policy, id),
            read_rosters,
            None,
        )
    }

    fn resolve_interlocutors_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        input: &InterlocutorResolutionInput,
        admit: &dyn Fn(&EntityId) -> Result<bool>,
        read_rosters: bool,
        container: Option<EntityId>,
    ) -> Result<InterlocutorSet> {
        let mut non_owner: Vec<Interlocutor> = Vec::with_capacity(input.parties.len());
        let mut seen_contact_refs: HashSet<String> = HashSet::new();

        for party in &input.parties {
            let entry = match party {
                InterlocutorPartyInput::ContactRef(id) => {
                    if !admit(id)? {
                        return Err(Error::EntityNotFound);
                    }
                    let record = self
                        .get_counterparty_contact_in_txn(rtxn, id)?
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
                        if let Some(contact_ref) = entry.contact_ref.as_ref()
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

    fn known_contact_interlocutor(
        &self,
        contact_ref: EntityId,
        label: &str,
        first_touch: CounterpartyFirstTouch,
    ) -> Result<Interlocutor> {
        let mut entry = Interlocutor::known_contact(contact_ref, label, first_touch);
        entry.relationship = relationship_label_for_contact(self, &contact_ref)?;
        Ok(entry)
    }

    /// Resolves a VOX-02 roster reference into non-owner participant entries.
    ///
    /// EVERY failure mode is an `Err` — missing roster, corrupt roster,
    /// storage fault — so the one caller has a single fail-closed branch. A
    /// roster that resolves but names nobody legitimately yields no entries.
    /// One party per distinct speaker: repeated segments of the same speaker
    /// key or placed identity collapse before the caller's contact-ref
    /// dedupe sees them. In a session bound to `container`, an unplaced
    /// speaker is read through its first entry there.
    fn voice_roster_parties(
        &self,
        rtxn: &heed::RoTxn<'_>,
        voice_session_ref: &str,
        container: Option<EntityId>,
    ) -> Result<Vec<Interlocutor>> {
        let roster = self
            .voice_session_roster_in_txn(rtxn, voice_session_ref)?
            .ok_or(Error::EntityNotFound)?;

        // A placed speaker is one party per identity it was placed as. An
        // unplaced speaker is one party per capture speaker key, whose
        // residual segments add nothing once any segment of that key is
        // placed. The owner names an unplaced speaker against this roster:
        // the ask's session is the roster ref, its speaker the speaker key,
        // and its revision the roster's (OF-365 P5).
        let unplaced = roster.unplaced_speakers();
        let mut parties = Vec::new();
        let mut seen_parties: HashSet<String> = HashSet::new();
        for segment in &roster.segments {
            let party = match &segment.evidence {
                VoiceAttributionEvidence::EnrolledPrint { subject_ref, .. } => {
                    format!("enrolled:{}", subject_ref.to_hex())
                }
                VoiceAttributionEvidence::InviteElimination { attendee_ref } => {
                    format!("invite:{}", attendee_ref.to_hex())
                }
                VoiceAttributionEvidence::ResidualCluster { .. } => {
                    if !unplaced.contains(&segment.speaker_key.as_str()) {
                        continue;
                    }
                    format!("speaker:{}", segment.speaker_key)
                }
            };
            if !seen_parties.insert(party) {
                continue;
            }
            // A bound speaker's identity is the one given on its entry
            // revision, which a later placement elsewhere does not move.
            let (answer, audience_ref) = match (&segment.evidence, container) {
                (VoiceAttributionEvidence::ResidualCluster { .. }, Some(container)) => self
                    .container_attendee_entry_in_txn(
                        rtxn,
                        container,
                        &ContainerAttendee::Speaker {
                            session_key: voice_session_ref.to_owned(),
                            speaker_key: segment.speaker_key.clone(),
                        },
                    )?
                    .map_or((None, None), |entry| {
                        (entry.identity, Some(entry.entry_ref))
                    }),
                (VoiceAttributionEvidence::ResidualCluster { .. }, None) => (
                    self.attendee_identity_in_txn(
                        rtxn,
                        voice_session_ref,
                        &segment.speaker_key,
                        roster.roster_revision,
                    )?,
                    None,
                ),
                _ => (None, None),
            };
            let mut party = self.voice_roster_party(rtxn, segment, answer)?;
            party.audience_ref = audience_ref;
            parties.push(party);
        }
        Ok(parties)
    }

    /// One roster segment as one non-owner entry.
    ///
    /// An enrolled OWNER print (no contact ref) is an `Unknown` entry flagged
    /// `owner_print_matched`; an enrolled CONTACT print keeps the
    /// `EnrolledVoicePrint` rung; an invite-eliminated attendee is resolved as
    /// an ordinary known contact, because elimination is a NON-biometric
    /// naming step and must not borrow the enrolled-print rung. A residual
    /// speaker the owner named (`answer`) resolves the same way, for the same
    /// reason; unnamed, it stays `Unknown`. A contact that is missing or
    /// revoked degrades to an anonymous `Unknown`.
    fn voice_roster_party(
        &self,
        rtxn: &heed::RoTxn<'_>,
        segment: &VoiceResolvedSegment,
        answer: Option<AttendeeIdentityChoice>,
    ) -> Result<Interlocutor> {
        let anonymous = || Interlocutor::unknown(segment.speaker_label.clone(), false);
        match &segment.evidence {
            VoiceAttributionEvidence::EnrolledPrint { .. } => {
                let Some(contact_ref) = segment.contact_ref else {
                    return Ok(Interlocutor::voice_matched_owner(
                        segment.speaker_label.clone(),
                    ));
                };
                let Some(record) = self.active_counterparty_contact(rtxn, &contact_ref)? else {
                    return Ok(anonymous());
                };
                let mut entry = Interlocutor::voice_matched_contact(
                    contact_ref,
                    &record.counterparty,
                    record.first_touch,
                );
                entry.relationship = relationship_label_for_contact(self, &contact_ref)?;
                Ok(entry)
            }
            VoiceAttributionEvidence::InviteElimination { attendee_ref } => {
                match self.active_counterparty_contact(rtxn, attendee_ref)? {
                    Some(record) => self.known_contact_interlocutor(
                        *attendee_ref,
                        &record.counterparty,
                        record.first_touch,
                    ),
                    None => Ok(anonymous()),
                }
            }
            VoiceAttributionEvidence::ResidualCluster { .. } => {
                let Some(AttendeeIdentityChoice::Contact(contact_ref)) = answer else {
                    return Ok(anonymous());
                };
                match self.active_counterparty_contact(rtxn, &contact_ref)? {
                    Some(record) => self.known_contact_interlocutor(
                        contact_ref,
                        &record.counterparty,
                        record.first_touch,
                    ),
                    None => Ok(anonymous()),
                }
            }
        }
    }

    fn active_counterparty_contact(
        &self,
        rtxn: &heed::RoTxn<'_>,
        contact_ref: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        Ok(self
            .get_counterparty_contact_in_txn(rtxn, contact_ref)?
            .filter(|record| record.status == CounterpartyContactStatus::Active))
    }
}

#[cfg(test)]
mod tests;
