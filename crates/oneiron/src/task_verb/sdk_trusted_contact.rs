//! The trusted-contact rows a host door answers (DOOR-140 A, OF-527): the
//! person names a trusted contact (`vault.trusted_contacts.name`), changes
//! whether they are asked first (`.dial.set`) and names a policy row's tier
//! (`.tier.set`); either side lists the relations it is a side of (`.list`)
//! and ends one (`.revoke`); the named contact consents, as an adult, to the
//! naming they were shown (`.consent`); and the person reads their open
//! concern asks (`.concern.asks`) and answers one (`.concern.authorize`).
//!
//! Each fn parses the refs and passes the engine exactly what it asks for:
//! the person and the contact come from the caller's proof and the time from
//! the host, never from the input, so no request asserts another person's
//! consent or adulthood.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::counterparty_contact::{
    TrustedContact, TrustedContactAsk, TrustedContactAskOutcome, TrustedContactDial,
    TrustedContactReach, TrustedContactTier,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::policy_model::PolicyModelConfig;
use crate::store::GateSystemNoticeRecord;
use crate::{EntityId, Vault};

/// `vault.trusted_contacts.name`'s input: the contact, another live PERSON of
/// this vault, by id; where the notice reaches them; and whether the person
/// is asked first. The caller's proof names the person.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactNameRequest {
    pub contact_ref: String,
    pub reach: TrustedContactReach,
    pub dial: TrustedContactDial,
}

/// `vault.trusted_contacts.list`'s input: none. The caller's proof names the
/// side whose relations it lists.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactsRequest {}

/// `vault.trusted_contacts.consent`'s input: the person who named the caller,
/// the naming `version` the caller was shown, and the caller's word that they
/// are an adult. The caller's proof names the contact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactConsentRequest {
    pub person_ref: String,
    pub version: u64,
    pub adult: bool,
}

/// `vault.trusted_contacts.revoke`'s input: the relation, by its two sides.
/// The engine checks the caller is one of them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactRevokeRequest {
    pub person_ref: String,
    pub contact_ref: String,
}

/// `vault.trusted_contacts.dial.set`'s input: the caller's named contact and
/// the dial to hold.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactDialRequest {
    pub contact_ref: String,
    pub dial: TrustedContactDial,
}

/// `vault.trusted_contacts.tier.set`'s input: one `RouteToHelp` policy row,
/// by its ref, and its tier.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactTierRequest {
    pub row_ref: String,
    pub tier: TrustedContactTier,
}

/// `vault.trusted_contacts.tier.set`'s answer: the row and the tier it now
/// holds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactTierSet {
    pub row_ref: String,
    pub tier: TrustedContactTier,
}

/// `vault.trusted_contacts.concern.asks`'s input: none. The caller's proof
/// names the person whose open asks it reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactAsksRequest {}

/// `vault.trusted_contacts.concern.authorize`'s input: one of the caller's
/// open asks, and their yes or no.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactAuthorizeRequest {
    pub ask_ref: String,
    pub yes: bool,
}

/// What one answer to an ask did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactAuthorizationOutcome {
    /// A yes: the fact-of-concern notice is staged on the outbound queue.
    /// Staged is not delivered: the contact has not been reached yet.
    Staged,
    /// A no: nothing is staged.
    Declined,
    /// The naming asked about was revoked or replaced: nothing is staged.
    Superseded,
}

/// `vault.trusted_contacts.concern.authorize`'s answer: the ask, the answer
/// given, what it did, and the system-voice notices that tell the person and
/// the model a notice was staged (none on a no or a superseded ask).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactAuthorization {
    pub ask_ref: String,
    pub yes: bool,
    pub outcome: TrustedContactAuthorizationOutcome,
    pub system_notices: Vec<GateSystemNoticeRecord>,
}

fn entity_ref(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} is not an entity id")))
}

/// `vault.trusted_contacts.name`: the person names (or names again) their
/// trusted contact. The relation is not live until the contact consents.
pub fn name_trusted_contact(
    vault: &Vault,
    person: &AuthenticatedOwner,
    input: TrustedContactNameRequest,
) -> MemoryResult<TrustedContact> {
    let contact = entity_ref("contact_ref", &input.contact_ref)?;
    Ok(vault.name_trusted_contact(
        person,
        contact,
        input.reach,
        input.dial,
        crate::unix_seconds_now(),
    )?)
}

/// `vault.trusted_contacts.list`: every relation the caller is a side of.
pub fn read_trusted_contacts(
    vault: &Vault,
    party: &AuthenticatedOwner,
    _input: TrustedContactsRequest,
) -> MemoryResult<Vec<TrustedContact>> {
    Ok(vault.trusted_contacts(party)?)
}

/// `vault.trusted_contacts.consent`: the named contact accepts, as an adult.
pub fn consent_trusted_contact(
    vault: &Vault,
    contact: &AuthenticatedOwner,
    input: TrustedContactConsentRequest,
) -> MemoryResult<TrustedContact> {
    let person = entity_ref("person_ref", &input.person_ref)?;
    Ok(vault.accept_trusted_contact(
        contact,
        person,
        input.version,
        input.adult,
        crate::unix_seconds_now(),
    )?)
}

/// `vault.trusted_contacts.revoke`: either side ends the relation.
pub fn revoke_trusted_contact(
    vault: &Vault,
    party: &AuthenticatedOwner,
    input: TrustedContactRevokeRequest,
) -> MemoryResult<TrustedContact> {
    let person = entity_ref("person_ref", &input.person_ref)?;
    let contact = entity_ref("contact_ref", &input.contact_ref)?;
    Ok(vault.revoke_trusted_contact(party, person, contact, crate::unix_seconds_now())?)
}

/// `vault.trusted_contacts.dial.set`: the person changes whether they are
/// asked first. The contact's consent stands.
pub fn set_trusted_contact_dial(
    vault: &Vault,
    person: &AuthenticatedOwner,
    input: TrustedContactDialRequest,
) -> MemoryResult<TrustedContact> {
    let contact = entity_ref("contact_ref", &input.contact_ref)?;
    Ok(vault.set_trusted_contact_dial(person, contact, input.dial)?)
}

/// `vault.trusted_contacts.tier.set`: the owner names one policy row's tier.
pub fn set_trusted_contact_tier(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TrustedContactTierRequest,
) -> MemoryResult<TrustedContactTierSet> {
    vault.set_trusted_contact_tier(owner, &input.row_ref, input.tier)?;
    Ok(TrustedContactTierSet {
        row_ref: input.row_ref,
        tier: input.tier,
    })
}

/// `vault.trusted_contacts.concern.asks`: the caller's open asks.
pub fn read_trusted_contact_asks(
    vault: &Vault,
    person: &AuthenticatedOwner,
    _input: TrustedContactAsksRequest,
) -> MemoryResult<Vec<TrustedContactAsk>> {
    Ok(vault.trusted_contact_asks(person)?)
}

/// `vault.trusted_contacts.concern.authorize`: the person answers one open
/// ask, once; a second answer is refused, never replayed. `config` words the
/// notices a yes returns, as the host configures them.
pub fn authorize_trusted_contact_ask(
    vault: &Vault,
    person: &AuthenticatedOwner,
    input: TrustedContactAuthorizeRequest,
    config: &PolicyModelConfig,
) -> MemoryResult<TrustedContactAuthorization> {
    let ask = entity_ref("ask_ref", &input.ask_ref)?;
    let answered = vault.answer_trusted_contact_ask(
        person,
        ask,
        input.yes,
        config,
        crate::unix_seconds_now(),
    )?;
    let (outcome, system_notices) = match answered {
        TrustedContactAskOutcome::Notified(notices) => {
            (TrustedContactAuthorizationOutcome::Staged, notices)
        }
        TrustedContactAskOutcome::Declined => {
            (TrustedContactAuthorizationOutcome::Declined, Vec::new())
        }
        TrustedContactAskOutcome::Superseded => {
            (TrustedContactAuthorizationOutcome::Superseded, Vec::new())
        }
    };
    Ok(TrustedContactAuthorization {
        ask_ref: ask.to_hex(),
        yes: input.yes,
        outcome,
        system_notices,
    })
}
