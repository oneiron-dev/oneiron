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
use crate::counterparty_contact::{CounterpartyContactStatus, CounterpartyFirstTouch};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

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
    /// 5. `voice_session_ref`: accepted and ignored.
    /// 6. Two inputs resolving to the same contact collapse to one entry;
    ///    label collision between Unknowns is allowed (labels are display
    ///    data).
    pub fn resolve_interlocutors(
        &self,
        input: &InterlocutorResolutionInput,
    ) -> Result<InterlocutorSet> {
        let mut non_owner: Vec<Interlocutor> = Vec::with_capacity(input.parties.len());
        let mut seen_contact_refs: HashSet<String> = HashSet::new();

        for party in &input.parties {
            let entry = match party {
                InterlocutorPartyInput::ContactRef(id) => {
                    let record = self
                        .get_counterparty_contact(id)?
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
                } => match self.find_counterparty_contact(identity_ref, counterparty)? {
                    Some((id, record)) if record.status == CounterpartyContactStatus::Active => {
                        self.known_contact_interlocutor(
                            id,
                            &record.counterparty,
                            record.first_touch,
                        )?
                    }
                    _ => Interlocutor::unknown(counterparty.clone(), false),
                },
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

        // ILD-3 (ONE-1518) fills the roster merge here: `voice_session_ref`
        // resolves to an empty roster until then.
        let _ = input.voice_session_ref.as_deref();

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
}

#[cfg(test)]
mod tests;
