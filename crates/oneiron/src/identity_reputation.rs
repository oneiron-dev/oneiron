//! ChannelIdentity reputation claims and warmup delivery floors (OF-347 R4).
//!
//! This module is intentionally engine-level: provider adapters translate
//! native webhook payloads into the typed signal inputs here, and dispatch
//! callers consume the per-identity clamp result before scheduling sends.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::cohort_claims::suppression::{SuppressionCause, SuppressionInput};

pub(crate) use crate::write_envelope::identity_reputation::validate_identity_reputation_claim_structure;
pub use crate::write_envelope::identity_reputation::{
    BOUNCE_CONSTRAINED_THRESHOLD, BOUNCE_DEGRADED_THRESHOLD, COMPLAINT_CONSTRAINED_THRESHOLD,
    COMPLAINT_DEGRADED_THRESHOLD, CONSTRAINED_REPUTATION_DAILY_CAP, DEGRADED_REPUTATION_DAILY_CAP,
    EmailReputationWebhookSignal, IDENTITY_REPUTATION_CLAIM_PREDICATES,
    IDENTITY_REPUTATION_SCHEMA_VERSION, IdentityAttestationTier, IdentityReputation,
    IdentityReputationSignal, IdentityReputationStatus, IdentitySendRateClamp, IdentityWarmupStage,
    PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER, PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE,
    PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE, PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
    PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS,
    PREDICATE_IDENTITY_REPUTATION_UPDATED_AT, PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE,
    WARMUP_COLD_DAILY_CAP, WARMUP_WARMING_DAILY_CAP, is_identity_reputation_claim_predicate,
};

/// What one provider webhook says happened to one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailDeliveryDisposition {
    /// The message was accepted by the receiving side.
    Delivered,
    /// A transient failure. Health moves; nothing is suppressed.
    SoftBounce,
    /// A permanent failure. This is the only disposition that suppresses.
    HardBounce,
    /// The recipient marked the message as spam.
    Complaint,
}

/// One normalized campaign email webhook.
///
/// Provider adapters translate their native payloads into this shape; provider
/// SDK parsing and provider-specific transport policy stay outside the engine,
/// and no provider-specific reputation state is kept anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignEmailWebhookEvent {
    /// The sending identity the webhook is about.
    pub identity_ref: EntityId,
    /// The recipient PERSON.
    pub person_ref: EntityId,
    /// Campaign the send belonged to, when the webhook names one.
    pub campaign_ref: Option<EntityId>,
    /// Channel the send went out on.
    pub channel: String,
    /// The persisted inbound webhook evidence.
    pub evidence_ref: EntityId,
    /// What happened to this message.
    pub disposition: EmailDeliveryDisposition,
    /// The identity-wide counters this webhook carries.
    pub aggregate: EmailReputationWebhookSignal,
    /// When the webhook was observed.
    pub observed_at: u64,
}

/// Everything one campaign email webhook moved.
///
/// `reputation` and `clamp` are RETURNED, not persisted: `claim_bodies` and
/// `clamp_send_rate` have always been pure producers whose callers own
/// persistence, and quietly writing them from here would make this the second
/// door that decides when reputation claims land. `suppression` is the opposite
/// case — it names claims that ARE durable, because a suppression the caller
/// could forget to write is a suppression that leaks.
#[derive(Debug, Clone, PartialEq)]
pub struct SenderHealthProjection {
    /// Reputation after the webhook's counters were folded in.
    pub reputation: IdentityReputation,
    /// The resulting per-identity send-rate clamp.
    pub clamp: IdentitySendRateClamp,
    /// The suppression a hard bounce wrote, if any.
    pub suppression: Option<crate::write_envelope::cohort_claims::suppression::SuppressionReceipt>,
    /// The campaign-pause owner ask this signal committed, or the existing
    /// open ask for the same [campaign, identity] when already Paused.
    pub campaign_pause_ask: Option<u64>,
}

/// Projects one campaign email webhook, opening its own transaction.
///
/// # Errors
///
/// See `project_campaign_email_webhook_in_txn`.
pub fn project_campaign_email_webhook(
    vault: &Vault,
    current: IdentityReputation,
    event: &CampaignEmailWebhookEvent,
    requested_daily_cap: u64,
) -> Result<SenderHealthProjection> {
    vault.with_write_txn_grouped(|wtxn| {
        project_campaign_email_webhook_in_txn(vault, wtxn, current, event, requested_daily_cap)
    })
}

/// Projects one campaign email webhook inside the caller's transaction.
///
/// The flow is the existing one, unchanged: signal → [`IdentityReputation::apply_adapter_signal`]
/// → [`IdentityReputation::claim_bodies`] → [`IdentityReputation::clamp_send_rate`].
/// The warm-up stage ladder and the four thresholds above stay the only health
/// state machine; no second one is introduced here.
///
/// Only [`EmailDeliveryDisposition::HardBounce`] suppresses. A soft bounce is a
/// transient failure and a complaint is a reputation fact — both move health and
/// the clamp, and neither writes a permanent `comm.do_not_contact` or a
/// suppressed membership. Suppressing on a transient failure would silently
/// retire reachable addresses, which no later signal can undo.
///
/// # Errors
///
/// Propagates signal validation, claim validation, and storage errors;
/// [`Error::InvalidClaimBody`] when a hard bounce cannot be recorded.
pub(crate) fn project_campaign_email_webhook_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    current: IdentityReputation,
    event: &CampaignEmailWebhookEvent,
    requested_daily_cap: u64,
) -> Result<SenderHealthProjection> {
    let mut reputation = current;
    reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(event.aggregate))?;
    let clamp = reputation.clamp_send_rate(event.identity_ref, requested_daily_cap);
    let campaign_pause_ask = crate::campaign::surface::project_campaign_complaint_pause_in_txn(
        vault,
        wtxn,
        event.campaign_ref,
        event.identity_ref,
        event.evidence_ref,
        reputation.complaint_rate,
    )?;
    let suppression = match event.disposition {
        EmailDeliveryDisposition::HardBounce => {
            Some(vault.store.record_hooks.apply_suppression_in_txn(
                vault,
                wtxn,
                SuppressionCause::HardBounce,
                &SuppressionInput {
                    person_ref: event.person_ref,
                    campaign_ref: event.campaign_ref,
                    channel: event.channel.clone(),
                    sender_ref: Some(event.identity_ref),
                    evidence_ref: event.evidence_ref,
                    occurred_at: event.observed_at,
                },
            )?)
        }
        EmailDeliveryDisposition::Delivered
        | EmailDeliveryDisposition::SoftBounce
        | EmailDeliveryDisposition::Complaint => None,
    };
    Ok(SenderHealthProjection {
        reputation,
        clamp,
        suppression,
        campaign_pause_ask,
    })
}
