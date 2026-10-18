//! The trusted-contact rows a host door answers (DOOR-140 A, OF-527): the
//! person names a trusted contact (`vault.trusted_contacts.name`), changes
//! whether they are asked first (`.dial.set`) and names a policy row's tier
//! (`.tier.set`); either side lists the relations it is a side of (`.list`)
//! and ends one (`.revoke`); the named contact consents, as an adult, to the
//! naming they were shown (`.consent`); and the person reads their open
//! concern asks (`.concern.asks`) and answers one (`.concern.authorize`).
//! DOOR-140 B: the person's own policy gate reads one conversation message
//! and, on a `RouteToHelp`, proposes the fact of concern
//! (`.concern.propose`); a notice's own sender delivers it
//! (`.concern.deliver`).
//!
//! Each fn parses the refs and passes the engine exactly what it asks for:
//! the person and the contact come from the caller's proof and the time from
//! the host, never from the input, so no request asserts another person's
//! consent or adulthood, a verdict, or a sender.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::counterparty_contact::{
    TrustedContact, TrustedContactAsk, TrustedContactAskOutcome, TrustedContactDial,
    TrustedContactNoticeAuthorization, TrustedContactReach, TrustedContactTier,
};
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
};
use crate::outbound::OutboundExecutionSink;
use crate::policy_model::{PolicyClassifyRequest, PolicyEnforcementAction, PolicyModelConfig};
use crate::store::GateSystemNoticeRecord;
use crate::{EntityId, Vault};

/// The record kind `.concern.propose` reads: one conversation message.
const CONCERN_RECORD_KIND: &str = "MESSAGE";

/// The audience of a notice told to the person and the model alike.
const USER_AND_MODEL: &str = "user_and_model";

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

/// `vault.trusted_contacts.concern.propose`'s input: one conversation
/// message the caller reads, by ref (`id` or `id@revision`). The policy gate
/// reads it; nothing else in the request shapes the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactConcernRequest {
    pub content_ref: String,
}

/// The one thing a trusted contact ever hears: that there is a concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactConcernFact {
    FactOfConcern,
}

/// `vault.trusted_contacts.concern.propose`'s answer: what the person's
/// policy gate settled for the message, the fact it proposes when that is a
/// `RouteToHelp` (none otherwise), the gate's receipt, the person's open
/// asks (all of them, not only one this call raised) and the notices told
/// to the person and the model. Never the message, the verdict or its
/// rationale.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactConcernProposal {
    pub action: String,
    pub fact: Option<TrustedContactConcernFact>,
    pub gate_receipt_ref: Option<String>,
    pub open_asks: Vec<TrustedContactAsk>,
    pub system_notices: Vec<GateSystemNoticeRecord>,
}

/// `vault.trusted_contacts.concern.deliver`'s input: none. The caller is the
/// sender: it delivers the next notice it is the stored sender of.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactDeliverRequest {}

/// `vault.trusted_contacts.concern.deliver`'s answer for one notice: the
/// fire, the relation it is for and what authorized it, the fact it carried,
/// and the dispatch's own facts. `delivered_to_channel` means the channel
/// took it, not that the contact read it. No message, transcript or target
/// address.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactDeliveryReceipt {
    pub fire_ref: String,
    pub person_ref: String,
    pub contact_ref: String,
    pub version: u64,
    pub channel: String,
    pub verb: String,
    pub authorization: TrustedContactNoticeAuthorization,
    pub fact: TrustedContactConcernFact,
    pub outcome: String,
    pub gate_decision_id: Option<String>,
    pub gate_outcome: String,
    pub gate_reason_codes: Vec<String>,
    pub receipt_id: String,
    pub occurred_at: u64,
    pub provider_ref: Option<String>,
    pub delivery_may_have_occurred: bool,
}

/// The one typed field `.concern.propose` reads from a message body.
#[derive(Deserialize)]
struct ConcernMessageBody {
    content: String,
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

/// The text of the one conversation message `content_ref` names, read under
/// the caller's own scope: a MESSAGE's `content`, and no other kind or field.
fn concern_message_text(memory: &Memory<'_>, content_ref: &str) -> MemoryResult<String> {
    let view = memory.get_entity(content_ref)?.value.ok_or_else(|| {
        MemoryError::not_found("no message the caller reads has that content_ref")
    })?;
    if view.kind != CONCERN_RECORD_KIND {
        return Err(MemoryError::bad_request(
            "content_ref names no conversation MESSAGE",
        ));
    }
    let body = view
        .body
        .and_then(|body| serde_json::from_value::<ConcernMessageBody>(body).ok())
        .filter(|body| !body.content.trim().is_empty())
        .ok_or_else(|| MemoryError::bad_request("the message carries no text"))?;
    Ok(body.content)
}

/// `vault.trusted_contacts.concern.propose`: the person's own owner-policy
/// gate reads one message the caller reads, fresh, for the proven person.
/// A `RouteToHelp` it settles fires the person's trusted contacts in the
/// gate's own transaction (an ask, or a just-call notice on the imminent
/// tier); this answers the fact only. With the owner policy off, or a pass
/// that wanted a safeguard model this host does not serve, it refuses: no
/// verdict is taken from the caller, and none is made up.
pub fn propose_trusted_contact_concern(
    memory: &Memory<'_>,
    person: &AuthenticatedOwner,
    input: TrustedContactConcernRequest,
    config: &PolicyModelConfig,
) -> MemoryResult<TrustedContactConcernProposal> {
    let vault = memory.vault();
    let content = concern_message_text(memory, &input.content_ref)?;
    let enabled = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.owner_policy_enabled()
    };
    if !enabled {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the vault's owner policy is off: no gate settles a RouteToHelp",
            &["The owner turns on owner policy and writes a RouteToHelp row first."],
        ));
    }
    let request = PolicyClassifyRequest::outbound_content(content)
        .with_caller_ref(memory.actor().to_hex())
        .with_concerned_person(person.clone());
    let enforcement = vault.enforce_policy_model_with_config(request, config)?;
    if enforcement.action == PolicyEnforcementAction::Skipped {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "the owner policy wanted a safeguard model this host does not serve; nothing was proposed",
            &["Write a deciding pattern for the RouteToHelp row, or serve a safeguard model."],
        ));
    }
    let fact = (enforcement.action == PolicyEnforcementAction::RouteToHelp)
        .then_some(TrustedContactConcernFact::FactOfConcern);
    Ok(TrustedContactConcernProposal {
        action: enforcement.action.as_str().to_owned(),
        fact,
        gate_receipt_ref: enforcement.receipt_ref,
        open_asks: vault.trusted_contact_asks(person)?,
        system_notices: enforcement
            .system_notices
            .into_iter()
            .filter(|notice| notice.audience == USER_AND_MODEL)
            .collect(),
    })
}

/// `vault.trusted_contacts.concern.deliver`: the caller delivers the next
/// notice it is the stored sender of, as itself, through `sink`. `None`
/// when none of its notices is eligible; another sender's never is.
pub fn deliver_trusted_contact_notice<S: OutboundExecutionSink>(
    memory: &Memory<'_>,
    _input: TrustedContactDeliverRequest,
    sink: &mut S,
) -> MemoryResult<Option<TrustedContactDeliveryReceipt>> {
    let delivered = memory
        .vault()
        .deliver_trusted_contact_notice(memory, sink)
        .map_err(crate::memory::facade_error_from_outbound_dispatch)?;
    Ok(
        delivered.map(|(notice, result)| TrustedContactDeliveryReceipt {
            fire_ref: notice.fire,
            person_ref: notice.person,
            contact_ref: notice.contact,
            version: notice.version,
            channel: notice.channel,
            verb: notice.verb,
            authorization: notice.authorization,
            fact: TrustedContactConcernFact::FactOfConcern,
            outcome: result.outcome.as_str().to_owned(),
            gate_decision_id: result.gate_decision_id,
            gate_outcome: result.gate_outcome,
            gate_reason_codes: result.gate_reason_codes,
            provider_ref: result.receipt.fields.get("provider_ref").cloned(),
            delivery_may_have_occurred: result
                .receipt
                .fields
                .get("delivery_may_have_occurred")
                .is_some_and(|value| value == "true"),
            receipt_id: result.receipt.receipt_id,
            occurred_at: result.receipt.occurred_at,
        }),
    )
}
