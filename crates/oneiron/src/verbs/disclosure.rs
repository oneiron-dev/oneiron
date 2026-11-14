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

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::disclosure::{
    DisclosureOfferRequest, DisclosureOffered, RevealAnswerRequest, RevealAnsweredView,
    RevealAskView, RevealAsksRequest, RevealOutcome,
};

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

pub fn disclosure_reveals_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: RevealAsksRequest,
) -> MemoryResult<Vec<RevealAskView>> {
    Ok(vault
        .secret_reveals(owner, input.pending, input.limit.unwrap_or(50).min(200))?
        .into_iter()
        .map(|ask| RevealAskView {
            receipt: super::secret::reveal_receipt(ask.receipt),
            state: ask.state.as_str().to_owned(),
            expires_at: ask.expires_at,
            disclosure: ask.disclosure,
            expected_digest: ask.once_digest.map(|digest| digest.to_hex()),
            grant_ref: ask.grant_ref,
        })
        .collect())
}

pub fn answer_disclosure_reveal_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: RevealAnswerRequest,
) -> MemoryResult<RevealAnsweredView> {
    let reveal = EntityId::from_hex(&input.reveal)
        .map_err(|_| MemoryError::bad_request("reveal is not an entity id"))?;
    let invalid = || MemoryError::bad_request("expected_digest must be 64 lowercase hex");
    let text = input.expected_digest;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut digest = [0_u8; 32];
    for (at, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).map_err(|_| invalid())?;
    }
    let answer = match input.outcome {
        RevealOutcome::Once => crate::secret_custody::SecretRevealAnswer::Once,
        RevealOutcome::Standing => crate::secret_custody::SecretRevealAnswer::Standing,
        RevealOutcome::Deny => crate::secret_custody::SecretRevealAnswer::Deny,
    };
    let answered = vault.answer_secret_reveal(owner, &reveal, &digest, answer)?;
    Ok(RevealAnsweredView {
        reveal: answered.reveal.to_hex(),
        outcome: answered.answer.as_str().to_owned(),
        receipt_ref: format!("gate:{}", answered.decision.to_hex()),
        grant_ref: answered.grant_ref,
    })
}
