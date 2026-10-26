//! Manual enrollment beside the saved-query MACRO ingress. It neither invents a
//! saved-query event nor runs the machine-only outward leg. The caller applies
//! the returned ordinary claim candidate through its existing write gate.

use super::reconcile::{IntakeSource, effective_member_in_txn, reconcile};
use crate::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    counterparty_do_not_contact_in_txn, encode_campaign_member_value,
};
use crate::campaign::surface::{CampaignLifecycle, campaign_type_byte, owned_campaign_in_txn};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::ports::TombstoneStoreRead;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Error, Result, Vault};

/// What one manual enrollment lands (FIX 9664, 10221).
pub(crate) struct ManualIntake {
    /// The ordinary claim candidate the caller's gate applies.
    pub(crate) candidate: ClaimCandidate,
    /// The effective membership value the candidate carries.
    pub(crate) value: CampaignMemberValue,
    /// Every admitted live head the candidate replaces. The caller closes
    /// them in its own writer once the gate admits the candidate.
    pub(crate) supersedes: Vec<EntityId>,
    /// When the candidate's state began: `now` for a new or enrolled
    /// membership, the kept state's own instant otherwise.
    pub(crate) occurred_start: u64,
}

/// A manual enrollment reconciles with the person's one membership in the
/// campaign rather than refusing it (FIX 9664, 10221): it cannot clear a
/// pause, suppression or exit, replace a held channel's sticky sender, or
/// forge a derived epoch, and it adds only channels the membership does not
/// hold. The candidate keeps the replaced head's isolation stamps and its
/// derivation. Every store-dependent guard runs in the transaction that
/// lands the claim.
pub(crate) fn manual_enrollment_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    person: EntityId,
    value: &CampaignMemberValue,
    evidence: &[EntityId],
    now: u64,
) -> Result<ManualIntake> {
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
    let effective = effective_member_in_txn(vault, txn, person, value.campaign)?;
    let reconciled = reconcile(effective.as_ref(), value, &IntakeSource::Manual, now);
    let mut candidate = ClaimCandidate::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(person),
        encode_campaign_member_value(&reconciled.value),
        1.0,
    )
    .with_evidence(rmpv::Value::Array(
        evidence
            .iter()
            .map(|id| rmpv::Value::from(id.to_hex()))
            .collect(),
    ));
    if let Some(effective) = &effective {
        candidate = with_isolation_stamps(candidate, &effective.body);
    }
    Ok(ManualIntake {
        candidate,
        value: reconciled.value,
        supersedes: effective.map(|member| member.heads).unwrap_or_default(),
        occurred_start: reconciled.kept_since.unwrap_or(now),
    })
}

/// `candidate` stamped exactly as `head` is: its world, relationship, scope,
/// facet and project. A replacement never re-scopes who may read the
/// membership.
fn with_isolation_stamps(mut candidate: ClaimCandidate, head: &ClaimBody) -> ClaimCandidate {
    if let Some(world) = head.world {
        candidate = candidate.with_world(world);
    }
    if let Some(relationship) = head.rel {
        candidate = candidate.with_relationship(relationship);
    }
    if let Some(scope) = &head.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    candidate.with_scope_stamps(head.scope_facet, head.scope_project)
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
