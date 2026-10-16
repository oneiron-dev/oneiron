//! `vault.disclosure.offer`: an agent OFFERS the owner a contact clearance
//! (OF-365, the ILDF2 consent channel). The door is
//! [`crate::Vault::offer_contact_disclosure`] under the caller's own verified
//! credential, which must carry the `propose_disclosure_widen` verb. The offer
//! confers no authority: only the owner settles it, at
//! `POST /v1/owner/disclosure/confirm`. The agent surface has no confirm row,
//! and the generic widen accept refuses a contact payload.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::consent::ContactDisclosureOffer;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// `vault.disclosure.offer`'s input: the clearance asked for one contact, the
/// owner whose answer it waits on, and when it lapses unanswered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureOfferRequest {
    /// The CID-7 contact the clearance is for, as 32 hex.
    pub contact: String,
    /// The exact clearance Scope asked for, in the canonical six-axis form.
    #[schemars(with = "serde_json::Value")]
    pub scope: Scope,
    /// Why, 1..=512 bytes; the owner reads it.
    pub purpose: String,
    /// The channel the disclosure travels on. A tap on one channel never
    /// clears another.
    pub channel: String,
    /// The one party the disclosure reaches.
    pub beneficiary: String,
    /// The private TASK ask this offer rides, when one exists.
    #[serde(default)]
    pub ask: Option<String>,
    /// The principal ref of the owner whose answer the offer waits on.
    pub owner_ref: String,
    /// When the offer lapses unanswered, in engine seconds.
    pub expires_at: u64,
}

/// `vault.disclosure.offer`'s answer: the filed offer, by the ref the owner
/// reads and answers it under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureOffered {
    pub proposal_ref: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `vault.disclosure.offer` on a handle: files the offer under the credential
/// the handle's host bound. An embedded handle has none and is refused; the
/// engine refuses any credential that is not a live agent's, single-use, or
/// without `propose_disclosure_widen`.
pub fn offer_contact_disclosure_as_caller(
    memory: &Memory<'_>,
    input: DisclosureOfferRequest,
) -> MemoryResult<DisclosureOffered> {
    let credential = memory.presented_credential().ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.disclosure.offer is an agent's offer under its own verified credential",
            &["Call it through a server, with the agent's paired credential."],
        )
    })?;
    let contact_ref = EntityId::from_hex(&input.contact)
        .map_err(|_| MemoryError::bad_request("contact is not an entity id"))?;
    let offer = ContactDisclosureOffer {
        contact_ref,
        scope: input.scope,
        purpose: input.purpose,
        channel: input.channel,
        beneficiary_ref: input.beneficiary,
        ask_ref: input.ask,
    };
    let proposal = memory.vault().offer_contact_disclosure(
        credential,
        offer,
        &input.owner_ref,
        input.expires_at,
    )?;
    Ok(DisclosureOffered {
        proposal_ref: proposal.proposal_ref,
        owner_ref: proposal.owner_ref,
        created_at: proposal.created_at,
        expires_at: proposal.expires_at,
    })
}
