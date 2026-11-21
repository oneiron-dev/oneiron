//! Typed public doors over the identity-ramp graduation offers (ARCH-0063
//! [INB-04]): the owner lists the standing offers its INBOX pile carries and
//! answers one by its offer id. Both are the owner's, under the owner's
//! proof; authority stays in the autonomy and consent doors.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::consent_graduation::api::{GraduationAnswer, GraduationSnooze};
use crate::error::{Error, GateError};
use oneiron_contracts::memory::MemoryResult;

use super::types::GraduationOffer;

/// One standing identity graduation offer: the scope it is made on, the
/// streak that earned it, and the volume bound auto would keep.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelIdentityGraduationOfferView {
    /// The offer id, also the payload of its `ramp:` INBOX row.
    pub offer: String,
    pub actor: String,
    pub identity: String,
    pub relationship_context: String,
    pub verb_class: String,
    pub counterparty_class: Option<String>,
    /// Approved-untouched reviews since the newest correction and the
    /// owner's last decline.
    pub unchanged_streak: u32,
    /// The outbound review receipts that streak counts, oldest first.
    pub evidence_refs: Vec<String>,
    /// The envelope's send bound, kept on auto.
    pub max_actions: u32,
    pub window_secs: u64,
    pub offered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityGraduationAnswerRequest {
    /// The offer id its INBOX row carries.
    pub offer: String,
    pub answer: GraduationAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelIdentityGraduationAnswerReceipt {
    pub offer: String,
    pub answer: GraduationAnswer,
    /// The rung the identity now sends at, on auto.
    pub rung: Option<String>,
    pub snooze: GraduationSnooze,
}

fn view(offer: GraduationOffer) -> MemoryResult<ChannelIdentityGraduationOfferView> {
    Ok(ChannelIdentityGraduationOfferView {
        offer: offer.scope.offer_id()?,
        actor: offer.scope.actor_ref.to_hex(),
        identity: offer.scope.identity_ref.to_hex(),
        relationship_context: offer.scope.relationship_context.as_str().to_owned(),
        verb_class: offer.scope.verb_class,
        counterparty_class: offer.scope.counterparty_class,
        unchanged_streak: offer.unchanged_streak,
        evidence_refs: offer.evidence_refs,
        max_actions: offer.proposed_envelope.max_actions,
        window_secs: offer.proposed_envelope.window_secs,
        offered_at: offer.offered_at,
    })
}

/// The standing offers, in scope order; reading grants nothing.
pub fn offers(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<ChannelIdentityGraduationOfferView>> {
    vault.recheck_owner(owner)?;
    vault
        .channel_identity_graduation_offers()?
        .into_iter()
        .map(view)
        .collect()
}

/// The owner's answer to one standing offer: auto mints the `mail.send`
/// grant over the offer's envelope and moves the rung; not_now and
/// manual_pinned record a decline, which restarts the streak.
pub fn answer(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ChannelIdentityGraduationAnswerRequest,
) -> MemoryResult<ChannelIdentityGraduationAnswerReceipt> {
    vault.recheck_owner(owner)?;
    let offer = vault
        .channel_identity_graduation_offer(&input.offer)?
        .ok_or(Error::Gate(GateError::InvalidConsentBound(
            "no identity graduation offer stands under this id",
        )))?;
    let (rung, snooze) = match input.answer {
        GraduationAnswer::Auto => {
            let mode = vault.accept_channel_identity_graduation_offer(&offer, owner)?;
            (Some(mode.rung.as_str().to_owned()), GraduationSnooze::None)
        }
        GraduationAnswer::NotNow => (
            None,
            vault
                .decline_channel_identity_graduation_offer(&offer, owner)?
                .into(),
        ),
        GraduationAnswer::ManualPinned => (
            None,
            vault
                .pin_channel_identity_graduation_offer(&offer, owner)?
                .into(),
        ),
    };
    Ok(ChannelIdentityGraduationAnswerReceipt {
        offer: input.offer,
        answer: input.answer,
        rung,
        snooze,
    })
}
