//! Moved from `crates/oneiron/src/verbs/trusted_contact.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::counterparty_contact::trusted_contact::TrustedContactAsk;
use crate::counterparty_contact::trusted_contact::TrustedContactDial;
use crate::counterparty_contact::trusted_contact::TrustedContactReach;
use crate::counterparty_contact::trusted_contact::TrustedContactTier;
use crate::counterparty_contact::trusted_contact_notice::TrustedContactNoticeAuthorization;
use oneiron_store::gate_decision::types::GateSystemNoticeRecord;
use serde::Deserialize;
use serde::Serialize;

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
    /// While the Gate holds the notice for the owner (`gate_outcome`
    /// `pending`), the approve-once digest his one-time press must name to
    /// release it, 64 lower-hex (FIX 6424), copied from the dispatch result.
    /// Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
}
