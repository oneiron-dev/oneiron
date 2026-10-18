//! Manual enrollment beside the saved-query MACRO ingress. It neither invents a
//! saved-query event nor runs the machine-only outward leg. The caller applies
//! the returned ordinary claim candidate through its existing write gate.

use crate::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    counterparty_do_not_contact_in_txn, encode_campaign_member_value,
    live_campaign_member_head_in_txn,
};
use crate::campaign::surface::{CampaignLifecycle, campaign_type_byte, owned_campaign_in_txn};
use crate::claim::ClaimSubject;
use crate::ports::TombstoneStoreRead;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Error, Result, Vault};

/// The manual path admits no existing head: enrollment cannot clear a pause,
/// suppression or exit, replace a sticky sender, or forge a derived epoch.
/// Every store-dependent guard runs in the transaction that lands the claim.
pub(crate) fn manual_enrollment_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    person: EntityId,
    value: &CampaignMemberValue,
    evidence: &[EntityId],
) -> Result<ClaimCandidate> {
    let campaign = owned_campaign_in_txn(
        vault,
        txn,
        actor,
        value.campaign,
        campaign_type_byte(vault)?,
    )?;
    if campaign.definition.lifecycle != CampaignLifecycle::Active {
        return Err(Error::InvalidClaimBody(
            "an archived campaign cannot enroll",
        ));
    }
    if vault.get_entity_type_in_txn(txn, &person)? != Some(crate::registry::ENTITY_TYPE_PERSON) {
        return Err(Error::InvalidClaimBody(
            "campaign membership requires a PERSON",
        ));
    }
    if evidence.is_empty() || value.channels.is_empty() {
        return Err(Error::InvalidClaimBody(
            "enrollment requires provenance and channel basis evidence",
        ));
    }
    if value.state != CampaignMemberState::Enrolled || value.derivation.is_some() {
        return Err(Error::InvalidClaimBody(
            "manual enrollment cannot supply machine derivation",
        ));
    }
    if live_campaign_member_head_in_txn(&vault.store, txn, person, value.campaign)?.is_some() {
        return Err(Error::ConcurrentWrite(
            "campaign membership already has a live head",
        ));
    }
    let mut channels = std::collections::BTreeSet::new();
    for CampaignMemberChannel {
        channel,
        sender_ref,
        ..
    } in &value.channels
    {
        if channel.is_empty() || !channels.insert(channel) {
            return Err(Error::InvalidClaimBody(
                "enrollment requires a nonempty unique channel set",
            ));
        }
        require_channel_sender_in_txn(vault, txn, channel, *sender_ref)?;
        if counterparty_do_not_contact_in_txn(
            &vault.store,
            txn,
            &person.to_hex(),
            Some(channel),
            "all",
        )? {
            return Err(Error::InvalidClaimBody(
                "suppression forbids campaign enrollment on this channel",
            ));
        }
    }
    Ok(ClaimCandidate::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(person),
        encode_campaign_member_value(value),
        1.0,
    )
    .with_evidence(rmpv::Value::Array(
        evidence
            .iter()
            .map(|id| rmpv::Value::from(id.to_hex()))
            .collect(),
    )))
}

/// Shared sender guard for authored program steps and manual enrollment.
pub(super) fn require_channel_sender_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    channel: &str,
    sender_ref: EntityId,
) -> Result<()> {
    let not_an_identity = || Error::InvalidClaimBody("sender_ref is not a live channel identity");
    if vault.store.port_deletion_state(txn, &sender_ref)?.deleted {
        return Err(not_an_identity());
    }
    let identity = match vault.get_channel_identity_in_txn(txn, &sender_ref) {
        Ok(Some(identity)) => identity,
        Ok(None) | Err(Error::InvalidEntityType(_)) => return Err(not_an_identity()),
        Err(error) => return Err(error),
    };
    if crate::counterparty_contact::normalize_channel_class(identity.channel())
        != crate::counterparty_contact::normalize_channel_class(channel)
    {
        return Err(Error::InvalidClaimBody(
            "sender_ref is a channel identity of another channel",
        ));
    }
    Ok(())
}
