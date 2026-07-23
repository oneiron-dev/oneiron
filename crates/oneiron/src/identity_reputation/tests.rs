use super::*;

use crate::test_util::entity;

#[test]
fn email_webhook_signal_updates_health_claims() -> Result<()> {
    let identity_ref = entity(0x51);
    let mut reputation = IdentityReputation::new(IdentityWarmupStage::Cold, 10);

    reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
        EmailReputationWebhookSignal::new(1_000, 3, 20, false, 20),
    ))?;

    assert_eq!(reputation.complaint_rate, 0.003);
    assert_eq!(reputation.bounce_rate, 20.0 / 1_020.0);
    assert_eq!(reputation.status(), IdentityReputationStatus::Constrained);

    for claim in reputation.claim_bodies(identity_ref) {
        validate_identity_reputation_claim_structure(&claim)?;
        assert_eq!(claim.subject, ClaimSubject::Entity(identity_ref));
    }
    Ok(())
}

#[test]
fn attestation_tier_c_constrains_send_rate_without_complaint_or_bounce() -> Result<()> {
    let identity_ref = entity(0xA7);
    let mut reputation = IdentityReputation::new(IdentityWarmupStage::Established, 10);

    reputation.apply_adapter_signal(IdentityReputationSignal::AttestationTier {
        tier: IdentityAttestationTier::C,
        observed_at: 11,
    })?;

    // No complaint/bounce pressure: the constrained status is driven solely by tier C.
    assert_eq!(reputation.complaint_rate, 0.0);
    assert_eq!(reputation.bounce_rate, 0.0);
    assert_eq!(reputation.status(), IdentityReputationStatus::Constrained);

    let clamp = reputation.clamp_send_rate(identity_ref, 1_000);
    assert_eq!(clamp.status, IdentityReputationStatus::Constrained);
    assert_eq!(clamp.health_cap, CONSTRAINED_REPUTATION_DAILY_CAP);
    assert_eq!(clamp.effective_daily_cap, CONSTRAINED_REPUTATION_DAILY_CAP);
    assert!(!clamp.rotate_proposal_required);
    Ok(())
}

#[test]
fn warmup_and_health_clamps_are_per_identity() -> Result<()> {
    let healthy_identity = entity(0x52);
    let degraded_identity = entity(0x53);
    let healthy = IdentityReputation::new(IdentityWarmupStage::Cold, 10);
    let mut degraded = IdentityReputation::new(IdentityWarmupStage::Established, 10);
    degraded.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
        EmailReputationWebhookSignal::new(1_000, 7, 10, false, 11),
    ))?;

    let healthy_clamp = healthy.clamp_send_rate(healthy_identity, 500);
    let degraded_clamp = degraded.clamp_send_rate(degraded_identity, 500);

    assert_eq!(healthy_clamp.identity_ref, healthy_identity);
    assert_eq!(healthy_clamp.effective_daily_cap, WARMUP_COLD_DAILY_CAP);
    assert!(!healthy_clamp.rotate_proposal_required);
    assert_eq!(degraded_clamp.identity_ref, degraded_identity);
    assert_eq!(
        degraded_clamp.effective_daily_cap,
        DEGRADED_REPUTATION_DAILY_CAP
    );
    assert!(degraded_clamp.rotate_proposal_required);
    Ok(())
}

#[test]
fn complaint_spike_clamps_and_lands_rotate_proposal_only() -> Result<()> {
    let identity_ref = entity(0x54);
    let mut reputation = IdentityReputation::new(IdentityWarmupStage::Established, 10);

    reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
        EmailReputationWebhookSignal::new(2_000, 18, 15, true, 11),
    ))?;

    let clamp = reputation.clamp_send_rate(identity_ref, 1_000);
    assert_eq!(clamp.status, IdentityReputationStatus::Degraded);
    assert_eq!(clamp.effective_daily_cap, DEGRADED_REPUTATION_DAILY_CAP);

    let proposal = reputation
        .rotation_proposal_claim(identity_ref)
        .expect("degraded identity proposes rotation");
    assert_eq!(proposal.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(proposal.source, Some(ClaimSource::Generated));
    validate_identity_reputation_claim_structure(&proposal)?;

    let Value::Map(entries) = &proposal.value else {
        panic!("proposal value is a map");
    };
    assert_eq!(require_str(entries, "action")?, "rotate");
    assert!(!require_bool(entries, "auto_rotate")?);
    Ok(())
}

#[test]
fn malformed_reputation_claims_fail_closed() {
    let bad_rate = ClaimBody::new(
        PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
        ClaimSubject::Entity(entity(0x55)),
        Value::F64(1.5),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    assert!(validate_identity_reputation_claim_structure(&bad_rate).is_err());

    let bad_proposal = ClaimBody::new(
        PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
        ClaimSubject::Entity(entity(0xD6)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(IDENTITY_REPUTATION_SCHEMA_VERSION),
            ),
            (Value::from("action"), Value::from("rotate")),
            (Value::from("auto_rotate"), Value::Boolean(true)),
            (
                Value::from("status"),
                Value::from(IdentityReputationStatus::Degraded.as_str()),
            ),
            (Value::from("complaint_rate"), Value::F64(0.01)),
            (Value::from("bounce_rate"), Value::F64(0.0)),
            (Value::from("spam_label_observations"), Value::from(0_u64)),
            (
                Value::from("warmup_stage"),
                Value::from(IdentityWarmupStage::Established.as_str()),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    assert!(validate_identity_reputation_claim_structure(&bad_proposal).is_err());
}
