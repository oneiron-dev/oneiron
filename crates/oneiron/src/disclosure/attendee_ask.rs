//! The unknown-attendee ask (OF-365, ILDF2 P4): a speaker the vault cannot
//! place raises "who is this?" to the owner, with tap-to-pick candidates.
//!
//! The ask is TASK question data over a durable reference: the trigger TURN
//! when one exists, and always a typed private `disclosure.attendee_ask`
//! CLAIM that freezes the session, speaker, roster revision and candidates.
//! One ask stands per unresolved speaker and revision, not per label or pack.
//! The owner's answer ([`Vault::resolve_attendee_identity`]) binds at most the
//! chosen live contact to this speaker on this revision. It never mints a
//! clearance and never enrolls a voice print: a rejected, unanswered or
//! unknown speaker stays unknown, and so public-only. The surface that shows
//! the ask is co-design; the engine emits only kinds, options and refs.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::counterparty_contact::{CounterpartyContactStatus, decode_counterparty_contact_body};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
use crate::store::Store;
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOptionId, TaskAskQuestion, TaskAskReceipt,
    TaskAskSpec, TaskAskTarget,
};

use super::tier_classification::{
    PREDICATE_DISCLOSURE_ATTENDEE_ASK, PREDICATE_DISCLOSURE_ATTENDEE_IDENTITY,
    read_stored_claim_body,
};

/// The stable option id of the "unknown / none of these" answer.
pub const ATTENDEE_UNKNOWN_OPTION: &str = "unknown";

const CANDIDATE_OPTION_PREFIX: &str = "contact-";
const MAX_ATTENDEE_KEY_BYTES: usize = 128;
const MAX_ATTENDEE_CANDIDATES: usize = 32;
const ASK_CLAIM_DOMAIN: &[u8] = b"oneiron.disclosure.attendee_ask.v1";
const IDENTITY_CLAIM_DOMAIN: &[u8] = b"oneiron.disclosure.attendee_identity.v1";
const IDENTITY_SLOT_DOMAIN: &[u8] = b"oneiron.disclosure.attendee_identity.slot.v1";

/// One speaker the vault cannot place, to ask the owner about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAttendeeAsk {
    /// Stable key of the session (room, call or chat) the speaker is in.
    pub session_key: String,
    /// Stable key of the speaker within that session.
    pub speaker_key: String,
    /// The roster revision the speaker was heard under. A later revision is
    /// a new question.
    pub roster_revision: u64,
    /// The durable TURN that raised the ask, when one exists.
    pub trigger_turn: Option<EntityId>,
    /// Live contacts the owner may pick from, in the engine's order.
    pub candidates: Vec<EntityId>,
    /// When the ask lapses unanswered (engine seconds).
    pub until: u64,
}

/// The owner's answer to one attendee ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendeeIdentityChoice {
    /// The speaker is this live contact, one of the ask's candidates.
    Contact(EntityId),
    /// None of these: the speaker stays unknown.
    Unknown,
}

impl AttendeeIdentityChoice {
    /// The stable TASK option this choice is answered with.
    pub fn option(self) -> MemoryResult<TaskAskOptionId> {
        match self {
            Self::Contact(contact) => {
                TaskAskOptionId::new(format!("{CANDIDATE_OPTION_PREFIX}{}", contact.to_hex()))
            }
            Self::Unknown => TaskAskOptionId::new(ATTENDEE_UNKNOWN_OPTION),
        }
    }

    /// The choice a TASK answer's option names, if it names one.
    #[must_use]
    pub fn from_option(option: &TaskAskOptionId) -> Option<Self> {
        if option.as_str() == ATTENDEE_UNKNOWN_OPTION {
            return Some(Self::Unknown);
        }
        option
            .as_str()
            .strip_prefix(CANDIDATE_OPTION_PREFIX)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .map(Self::Contact)
    }
}

/// The owner's recorded answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttendeeIdentityResolution {
    /// The `disclosure.attendee_ask` CLAIM answered.
    pub ask_ref: EntityId,
    pub roster_revision: u64,
    pub choice: AttendeeIdentityChoice,
    /// The private `disclosure.attendee_identity` CLAIM that records it.
    pub identity_ref: EntityId,
}

/// The frozen question one ask CLAIM carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AttendeeAskRecord {
    session_key: String,
    speaker_key: String,
    roster_revision: u64,
    trigger_turn: Option<EntityId>,
    candidates: Vec<EntityId>,
}

impl AttendeeAskRecord {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::from("session"), Value::from(self.session_key.as_str())),
            (Value::from("speaker"), Value::from(self.speaker_key.as_str())),
            (Value::from("revision"), Value::from(self.roster_revision)),
            (
                Value::from("turn"),
                self.trigger_turn.map_or(Value::Nil, id_value),
            ),
            (
                Value::from("candidates"),
                Value::Array(self.candidates.iter().copied().map(id_value).collect()),
            ),
        ])
    }

    fn validate(&self) -> Result<()> {
        for key in [&self.session_key, &self.speaker_key] {
            if key.trim().is_empty() || key.trim() != key || key.len() > MAX_ATTENDEE_KEY_BYTES {
                return Err(invalid_ask());
            }
        }
        let distinct: BTreeSet<_> = self.candidates.iter().collect();
        if self.roster_revision == 0
            || self.candidates.len() > MAX_ATTENDEE_CANDIDATES
            || distinct.len() != self.candidates.len()
        {
            return Err(invalid_ask());
        }
        Ok(())
    }
}

/// Strict decode of a `disclosure.attendee_ask` value; the claim door's
/// structural validator.
pub(super) fn decode_attendee_ask_value(value: &Value) -> Result<AttendeeAskRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_ask());
    };
    let [
        (session_key, session),
        (speaker_key, speaker),
        (revision_key, revision),
        (turn_key, turn),
        (candidates_key, Value::Array(candidates)),
    ] = entries.as_slice()
    else {
        return Err(invalid_ask());
    };
    if [session_key, speaker_key, revision_key, turn_key, candidates_key]
        .iter()
        .map(|key| key.as_str())
        .ne(["session", "speaker", "revision", "turn", "candidates"].map(Some))
    {
        return Err(invalid_ask());
    }
    let text = |value: &Value| value.as_str().map(str::to_owned).ok_or_else(invalid_ask);
    let record = AttendeeAskRecord {
        session_key: text(session)?,
        speaker_key: text(speaker)?,
        roster_revision: revision.as_u64().ok_or_else(invalid_ask)?,
        trigger_turn: match turn {
            Value::Nil => None,
            turn => Some(decode_id(turn)?),
        },
        candidates: candidates
            .iter()
            .map(decode_id)
            .collect::<Result<Vec<_>>>()?,
    };
    record.validate()?;
    Ok(record)
}

/// Strict decode of a `disclosure.attendee_identity` value.
pub(super) fn decode_attendee_identity_value(
    value: &Value,
) -> Result<(u64, AttendeeIdentityChoice)> {
    let Value::Map(entries) = value else {
        return Err(invalid_ask());
    };
    let [(revision_key, revision), (choice_key, choice)] = entries.as_slice() else {
        return Err(invalid_ask());
    };
    if revision_key.as_str() != Some("revision") || choice_key.as_str() != Some("choice") {
        return Err(invalid_ask());
    }
    let choice = match choice {
        Value::String(text) if text.as_str() == Some(ATTENDEE_UNKNOWN_OPTION) => {
            AttendeeIdentityChoice::Unknown
        }
        contact => AttendeeIdentityChoice::Contact(decode_id(contact)?),
    };
    Ok((revision.as_u64().ok_or_else(invalid_ask)?, choice))
}

fn identity_value(revision: u64, choice: AttendeeIdentityChoice) -> Value {
    Value::Map(vec![
        (Value::from("revision"), Value::from(revision)),
        (
            Value::from("choice"),
            match choice {
                AttendeeIdentityChoice::Contact(contact) => id_value(contact),
                AttendeeIdentityChoice::Unknown => Value::from(ATTENDEE_UNKNOWN_OPTION),
            },
        ),
    ])
}

/// The deterministic ask CLAIM id: one per session, speaker and revision.
pub fn attendee_ask_ref(session_key: &str, speaker_key: &str, revision: u64) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASK_CLAIM_DOMAIN);
    for field in [
        session_key.as_bytes(),
        speaker_key.as_bytes(),
        &revision.to_be_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    derived_id(hasher)
}

fn attendee_identity_ref(ask_ref: &EntityId) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_CLAIM_DOMAIN);
    hasher.update(ask_ref.as_bytes());
    derived_id(hasher)
}

/// The owner-decision slot one answer takes. The identity CLAIM id is a
/// public derivation any claim writer can compute, so the slot, which only an
/// owner door takes, is what makes an answer the owner's.
fn attendee_identity_slot(identity_ref: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_SLOT_DOMAIN);
    hasher.update(identity_ref.as_bytes());
    *hasher.finalize().as_bytes()
}

fn derived_id(hasher: blake3::Hasher) -> Result<EntityId> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|_| invalid_ask())
}

impl Memory<'_> {
    /// Raises "who is this?" for one unplaced speaker to the vault's owners.
    ///
    /// The ask freezes its question in a private `disclosure.attendee_ask`
    /// CLAIM, then asks over the trigger TURN (or that CLAIM when there is
    /// none) with one stable option per live candidate plus
    /// [`ATTENDEE_UNKNOWN_OPTION`]. A repeat for the same speaker and
    /// revision replays the standing ask. Raising asks widens nothing: until
    /// the owner answers, the speaker is unknown and public-only.
    pub fn raise_unknown_attendee_ask(
        &self,
        ask: &UnknownAttendeeAsk,
    ) -> MemoryResult<TaskAskReceipt> {
        let record = AttendeeAskRecord {
            session_key: ask.session_key.clone(),
            speaker_key: ask.speaker_key.clone(),
            roster_revision: ask.roster_revision,
            trigger_turn: ask.trigger_turn,
            candidates: ask.candidates.clone(),
        };
        record.validate()?;
        let ask_ref = attendee_ask_ref(&ask.session_key, &ask.speaker_key, ask.roster_revision)?;
        let vault = self.vault();
        let owners = vault.with_write_txn_grouped(|txn| {
            for candidate in &record.candidates {
                require_live_contact_in_txn(&vault.store, &*txn, candidate)?;
            }
            match read_stored_claim_body(&vault.store, &*txn, &ask_ref)? {
                Some(body) if body.predicate == PREDICATE_DISCLOSURE_ATTENDEE_ASK => {
                    if decode_attendee_ask_value(&body.value)? != record {
                        return Err(invalid_ask());
                    }
                }
                Some(_) => return Err(invalid_ask()),
                None => {
                    let claim = ClaimBody::new(
                        PREDICATE_DISCLOSURE_ATTENDEE_ASK,
                        ClaimSubject::Entity(self.actor()),
                        record.to_value(),
                        1.0,
                        ClaimApprovalStatus::Auto,
                        ClaimLifecycleStatus::Active,
                    )?;
                    let now = vault.store.clock.now_recorded_at();
                    vault.put_disclosure_claim_in_txn(txn, &ask_ref, &claim, now)?;
                }
            }
            crate::policy_model::owners_in_txn(vault, &*txn)
        })?;
        if owners.is_empty() {
            return Err(MemoryError::bad_request("attendee ask has no vault owner"));
        }
        let ask_claim = ConsultPayloadRef::Claim(ask_ref);
        let mut question = TaskAskQuestion::new(
            ask.trigger_turn
                .map_or(ask_claim, ConsultPayloadRef::Turn),
        );
        if ask.trigger_turn.is_some() {
            question.context_refs.push(ask_claim);
        }
        question.revision = ask.roster_revision;
        for choice in record
            .candidates
            .iter()
            .copied()
            .map(AttendeeIdentityChoice::Contact)
            .chain([AttendeeIdentityChoice::Unknown])
        {
            let text = match choice {
                AttendeeIdentityChoice::Contact(contact) => contact.to_hex(),
                AttendeeIdentityChoice::Unknown => ATTENDEE_UNKNOWN_OPTION.to_owned(),
            };
            question.options.insert(choice.option()?, text);
        }
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(owners.into_iter().collect())),
            question,
            Some(ask.until),
            TaskAskDefault::Hold,
        );
        spec.intent_key = format!("{PREDICATE_DISCLOSURE_ATTENDEE_ASK}/{}", ask_ref.to_hex());
        self.tasks_ask(&spec)
    }
}

impl Vault {
    /// Records the owner's answer to one attendee ask, once.
    ///
    /// The answer must name this ask's revision and either one of its frozen
    /// candidates, still a live active contact, or
    /// [`AttendeeIdentityChoice::Unknown`]. It lands as a private
    /// `disclosure.attendee_identity` CLAIM on the ask. It mints no clearance
    /// and enrolls no voice print: an identified speaker reaches only what
    /// that contact is already cleared for.
    pub fn resolve_attendee_identity(
        &self,
        owner: &AuthenticatedOwner,
        ask_ref: &EntityId,
        roster_revision: u64,
        choice: AttendeeIdentityChoice,
    ) -> Result<AttendeeIdentityResolution> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let body = read_stored_claim_body(&self.store, &*txn, ask_ref)?
                .filter(|body| {
                    body.predicate == PREDICATE_DISCLOSURE_ATTENDEE_ASK
                        && body.lifecycle == ClaimLifecycleStatus::Active
                })
                .ok_or(Error::EntityNotFound)?;
            let record = decode_attendee_ask_value(&body.value)?;
            if record.roster_revision != roster_revision {
                return Err(invalid_ask());
            }
            if let AttendeeIdentityChoice::Contact(contact) = choice {
                if !record.candidates.contains(&contact) {
                    return Err(invalid_ask());
                }
                require_live_contact_in_txn(&self.store, &*txn, &contact)?;
            }
            let identity_ref = attendee_identity_ref(ask_ref)?;
            // The first owner answer is the only one. A claim already at the
            // id without the slot is not an answer, and is overwritten.
            let decision_id = crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?);
            self.take_decision_slot_in_txn(txn, &attendee_identity_slot(&identity_ref), decision_id)?;
            let claim = ClaimBody::new(
                PREDICATE_DISCLOSURE_ATTENDEE_IDENTITY,
                ClaimSubject::Entity(*ask_ref),
                identity_value(roster_revision, choice),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            self.put_disclosure_claim_in_txn(txn, &identity_ref, &claim, now)?;
            Ok(AttendeeIdentityResolution {
                ask_ref: *ask_ref,
                roster_revision,
                choice,
                identity_ref,
            })
        })
    }

    /// The owner's recorded answer for one speaker on one roster revision;
    /// `None` while unanswered, which reads as unknown.
    pub fn attendee_identity(
        &self,
        session_key: &str,
        speaker_key: &str,
        roster_revision: u64,
    ) -> Result<Option<AttendeeIdentityChoice>> {
        let txn = self.store.env.read_txn()?;
        self.attendee_identity_in_txn(&txn, session_key, speaker_key, roster_revision)
    }

    /// [`Self::attendee_identity`] as `txn` reads it.
    pub(crate) fn attendee_identity_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        session_key: &str,
        speaker_key: &str,
        roster_revision: u64,
    ) -> Result<Option<AttendeeIdentityChoice>> {
        let ask_ref = attendee_ask_ref(session_key, speaker_key, roster_revision)?;
        let identity_ref = attendee_identity_ref(&ask_ref)?;
        match self.ensure_decision_slot_open_in_txn(txn, &attendee_identity_slot(&identity_ref)) {
            Ok(()) => return Ok(None),
            Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => {}
            Err(error) => return Err(error),
        }
        let Some(body) = read_stored_claim_body(&self.store, txn, &identity_ref)? else {
            return Ok(None);
        };
        if body.predicate != PREDICATE_DISCLOSURE_ATTENDEE_IDENTITY
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Ok(None);
        }
        let (revision, choice) = decode_attendee_identity_value(&body.value)?;
        Ok((revision == roster_revision).then_some(choice))
    }
}

/// A candidate or a chosen identity is a live, active CID-7 contact.
fn require_live_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    contact: &EntityId,
) -> Result<()> {
    let raw = store
        .port_entity_record(txn, contact)?
        .map(|row| row.encode())
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    if !crate::vault::live_entity_row_in_txn(store, txn, contact)?.is_live()
        || decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?.status
            != CounterpartyContactStatus::Active
    {
        return Err(invalid_ask());
    }
    Ok(())
}

fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn decode_id(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_ask());
    };
    EntityId::from_bytes(bytes.as_slice().try_into().map_err(|_| invalid_ask())?)
        .map_err(|_| invalid_ask())
}

fn invalid_ask() -> Error {
    Error::InvalidClaimBody("disclosure.attendee_ask value invalid")
}
