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

#[test]
fn health_claims_land_on_delegated_rows_exactly_as_on_dedicated_rows() -> Result<()> {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, DelegatedGrant,
        DelegatedGrantScope,
    };
    use crate::config::VaultConfig;
    use crate::test_util::open_test_vault_with;

    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let (_tmp, vault) = open_test_vault_with(cfg);

    let agent = entity(0x5A);
    let dedicated_id = entity(0x5B);
    let delegated_id = entity(0x5C);

    vault.create_channel_identity(
        &dedicated_id,
        &ChannelIdentity::requested(
            "email",
            "agent@ours.test",
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent),
            1_000,
        ),
    )?;
    vault.create_channel_identity(
        &delegated_id,
        &ChannelIdentity::requested_delegated(
            "email",
            "member@member-owned.test",
            ChannelIdentityBinding::agent(agent),
            DelegatedGrant::new(
                "gmail-delegated:member@member-owned.test",
                vec![DelegatedGrantScope::MailRead],
            ),
            1_000,
        ),
    )?;
    assert_eq!(
        vault
            .get_channel_identity(&delegated_id)?
            .expect("delegated row")
            .shape,
        ChannelIdentityShape::DelegatedGrant
    );

    // The same bounce/complaint pressure on both rows. Reputation reads the
    // identity ref, never the shape, so a delegated mailbox's health is
    // scored, clamped, and claimed on exactly the same terms.
    let signal = EmailReputationWebhookSignal::new(1_000, 3, 20, false, 20);
    let mut dedicated = IdentityReputation::new(IdentityWarmupStage::Established, 10);
    let mut delegated = IdentityReputation::new(IdentityWarmupStage::Established, 10);
    dedicated.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(signal))?;
    delegated.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(signal))?;

    assert_eq!(dedicated.complaint_rate, delegated.complaint_rate);
    assert_eq!(dedicated.bounce_rate, delegated.bounce_rate);
    assert_eq!(dedicated.status(), delegated.status());

    let dedicated_claims = dedicated.claim_bodies(dedicated_id);
    let delegated_claims = delegated.claim_bodies(delegated_id);
    assert_eq!(dedicated_claims.len(), delegated_claims.len());
    for (ours, theirs) in dedicated_claims.iter().zip(delegated_claims.iter()) {
        validate_identity_reputation_claim_structure(ours)?;
        validate_identity_reputation_claim_structure(theirs)?;
        assert_eq!(ours.predicate, theirs.predicate);
        assert_eq!(ours.value, theirs.value);
        assert_eq!(ours.subject, ClaimSubject::Entity(dedicated_id));
        assert_eq!(theirs.subject, ClaimSubject::Entity(delegated_id));
    }

    let dedicated_clamp = dedicated.clamp_send_rate(dedicated_id, 500);
    let delegated_clamp = delegated.clamp_send_rate(delegated_id, 500);
    assert_eq!(dedicated_clamp.status, delegated_clamp.status);
    assert_eq!(dedicated_clamp.health_cap, delegated_clamp.health_cap);
    assert_eq!(
        dedicated_clamp.effective_daily_cap,
        delegated_clamp.effective_daily_cap
    );
    Ok(())
}
