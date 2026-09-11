//! Gate evaluator core: fail-closed default, criticality matrix, reason codes, and metrics.

use super::*;
use crate::error::GateError;

#[test]
fn gate_metrics_snapshot_has_stable_privacy_preserving_labels() {
    let snapshot = GateMetrics::default().snapshot();
    assert_eq!(
        snapshot.counters().len(),
        GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT
    );

    let labels = snapshot
        .counters()
        .iter()
        .map(|counter| (counter.outcome().as_str(), counter.reason_class().as_str()))
        .collect::<Vec<_>>();
    for counter in snapshot.counters() {
        assert_eq!(
            counter.count(),
            snapshot.count(counter.outcome(), counter.reason_class())
        );
    }
    assert!(labels.contains(&("allow", "allow")));
    assert!(labels.contains(&("pending", "actor_ceiling")));
    assert!(labels.contains(&("pending", "source_trust")));
    assert!(labels.contains(&("deny", "policy_fail_closed")));
}

#[test]
fn gate_metrics_counters_advance_for_representative_decisions() {
    let metrics = GateMetrics::default();
    let before = metrics.snapshot();
    metrics.record_decision(&GateDecision::allow());
    metrics.record_decision(&GateDecision::deny(GateReasonCode::DenyPolicyFailClosed));
    metrics.record_decision(&GateDecision::pending(vec![
        GateReasonCode::PendingSourceTrust,
        GateReasonCode::PendingCriticalityFloor,
    ]));
    let after = metrics.snapshot();

    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Allow,
        GateMetricReasonClass::Allow,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Deny,
        GateMetricReasonClass::PolicyFailClosed,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Pending,
        GateMetricReasonClass::SourceTrust,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Pending,
        GateMetricReasonClass::CriticalityFloor,
        1,
    );
}

#[test]
fn gate_metrics_advance_at_claim_write_chokepoint_without_double_counting() -> Result<()> {
    let (_allow_tmp, allow_vault) = temp_vault();
    let allow_before = allow_vault.diagnostics().gate.snapshot();
    let mut allow_policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut allow_policy);
    put_policy_manifest_bytes(&allow_vault, test_id(0x40), &allow_policy)?;
    let allow_body = source_trust_claim(ClaimSource::UserStated);
    let (allow_candidate, allow_envelope) = claim_candidate_write_parts(&allow_vault, &allow_body)?;
    allow_vault
        .batch()
        .claim_candidate(
            &test_id(0x41),
            allow_candidate,
            &allow_envelope,
            test_time(3),
            3,
        )
        .commit()?;

    let allow_after = allow_vault.diagnostics().gate.snapshot();

    let (_pending_tmp, pending_vault) = temp_vault();
    let pending_before = pending_vault.diagnostics().gate.snapshot();
    put_policy_manifest_bytes(
        &pending_vault,
        test_id(0x5F),
        &encode_policy_manifest(vec![]),
    )?;
    let pending_body = source_trust_claim(ClaimSource::UserStated);
    let (pending_candidate, pending_envelope) =
        claim_candidate_write_parts(&pending_vault, &pending_body)?;
    let pending_err = pending_vault
        .batch()
        .claim_candidate(
            &test_id(0x43),
            pending_candidate,
            &pending_envelope,
            test_time(3),
            3,
        )
        .commit()
        .expect_err("untrusted actor class must remain pending");
    assert_gate_rejected(pending_err, "pending", &["gate.pending.actor_ceiling"]);

    let pending_after = pending_vault.diagnostics().gate.snapshot();

    let (_deny_tmp, deny_vault) = temp_vault();
    let deny_before = deny_vault.diagnostics().gate.snapshot();
    put_policy_manifest_bytes(&deny_vault, test_id(0x45), b"not-msgpack")?;
    let deny_body = source_trust_claim(ClaimSource::UserStated);
    let (deny_candidate, deny_envelope) = claim_candidate_write_parts(&deny_vault, &deny_body)?;
    let deny_err = deny_vault
        .batch()
        .claim_candidate(
            &test_id(0x44),
            deny_candidate,
            &deny_envelope,
            test_time(3),
            3,
        )
        .commit()
        .expect_err("missing policy manifest must fail closed");
    assert_gate_rejected(deny_err, "deny", &["gate.deny.policy_fail_closed"]);

    let deny_after = deny_vault.diagnostics().gate.snapshot();

    // One counter set per vault, so each verdict is read where it was decided.
    assert_metric_counter_advanced(
        &allow_before,
        &allow_after,
        GateOutcome::Allow,
        GateMetricReasonClass::Allow,
        1,
    );
    assert_metric_counter_advanced(
        &pending_before,
        &pending_after,
        GateOutcome::Pending,
        GateMetricReasonClass::ActorCeiling,
        1,
    );
    assert_metric_counter_advanced(
        &deny_before,
        &deny_after,
        GateOutcome::Deny,
        GateMetricReasonClass::PolicyFailClosed,
        1,
    );
    Ok(())
}

#[test]
fn gate_evaluator_default_policy_fails_closed_with_typed_denial() {
    let policy = PolicyManifestResolution::default();
    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::DenyPolicyFailClosed]
    );
    let err = Error::Gate(GateError::GateWriteRejected {
        outcome: decision.outcome().as_str(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str())
            .collect(),
    });
    let typed = err
        .gate_denial()
        .expect("default fail-closed denial must be typed");
    assert_eq!(typed.outcome(), GateDenialOutcome::Deny);
    assert_eq!(
        typed.reason_codes(),
        &[GateDenialReason::DenyPolicyFailClosed]
    );
}

#[test]
fn gate_evaluator_actor_source_criticality_matrix() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x71), &data)?;
    let policy = resolve(&vault)?;

    let cases = [
        (
            "auto actor trusted source normal criticality",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
            GateOutcome::Allow,
            vec![GateReasonCode::Allow],
        ),
        (
            "auto actor trusted source critical floor",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingCriticalityFloor],
        ),
        (
            "auto actor low source trust normal criticality",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingSourceTrust],
        ),
        (
            "auto actor low source trust critical floor",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingSourceTrust,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
        (
            "proposed actor trusted source normal criticality",
            Some("probation"),
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingActorCeiling],
        ),
        (
            "proposed actor trusted source critical floor",
            Some("probation"),
            ClaimSource::UserStated,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
        (
            "proposed actor low source trust normal criticality",
            Some("probation"),
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingSourceTrust,
            ],
        ),
        (
            "proposed actor low source trust critical floor",
            Some("probation"),
            ClaimSource::ToolOutput,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingSourceTrust,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
    ];

    for (name, actor_ref, source, criticality, outcome, reasons) in cases {
        let input = gate_evaluator_input("first_party", actor_ref, source, criticality);
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), outcome, "{name}");
        assert_eq!(decision.reason_codes(), reasons.as_slice(), "{name}");
        assert!(
            decision
                .reason_codes()
                .iter()
                .all(|code| code.as_str().starts_with("gate.")),
            "{name}: reason codes must be stable gate.* strings"
        );
    }

    Ok(())
}

#[test]
fn gate_evaluator_denial_reason_codes_are_stable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x72), &data)?;
    let policy = resolve(&vault)?;

    let mut missing_actor_class = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_actor_class.actor.actor_class = " \t ".to_owned();
    let decision = policy.evaluate_gate(&missing_actor_class);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_actor_class"]
    );

    let mut missing_actor_provenance = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_actor_provenance.provenance.actor_entity_ref = None;
    let decision = policy.evaluate_gate(&missing_actor_provenance);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_actor_provenance"]
    );

    let mut missing_policy_version = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_policy_version.policy_manifest_version.clear();
    let decision = policy.evaluate_gate(&missing_policy_version);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_policy_manifest_version"]
    );

    let fail_closed_policy = PolicyManifestResolution::default();
    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    let decision = fail_closed_policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.policy_fail_closed"]
    );

    Ok(())
}

#[test]
fn gate_evaluator_missing_source_preserves_write_gate_semantics() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x74), &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::ToolOutput,
        PolicyCriticality::Normal,
    );
    input.source = None;
    input.sensitivity_band = None;

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    let lineage = crate::write_envelope::SourceLineage::of(ClaimSource::Generated)
        .with(ClaimSource::ToolOutput);
    let decision = policy.evaluate_gate_with_lineage(&input, Some(&lineage));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    input.provenance.actor_entity_ref = None;
    let decision = policy.evaluate_gate_with_lineage(&input, Some(&lineage));
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_actor_provenance"]
    );

    Ok(())
}

/// ONE-1645 write-path consequence, deliberate: a source under a band-capped
/// trust row (`max_auto_sensitivity = 1`) still auto-approves an explicitly
/// public claim, but an UNSTAMPED claim now reads the band-2 floor and
/// exceeds the cap — it queues for consent instead of auto-writing. Hosts
/// restore auto by stamping `public`; that is the floor doing its job, not a
/// regression.
#[test]
fn gate_source_trust_unstamped_claim_hits_floor_band() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 1)]);
    put_policy_manifest_bytes(&vault, test_id(0x77), &data)?;
    let policy = resolve(&vault)?;

    let table: [(&str, Option<Value>, bool); 3] = [
        (
            "explicit public stamp",
            Some(Value::Map(vec![(
                Value::from("sensitivity"),
                Value::from("public"),
            )])),
            true,
        ),
        ("unstamped: no scope map", None, false),
        (
            "unstamped: scope map without a sensitivity key",
            Some(Value::Map(vec![(
                Value::from("federated_original_source"),
                Value::from("user_stated"),
            )])),
            false,
        ),
    ];
    for (label, scope, expect_auto) in table {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.scope = scope;
        // The manifest's row carries no `actor_ref`, so it is class-wide and
        // answers an unattributed write exactly as it answers an attributed one.
        let allowed = check_claim_source_trust(&body, None, &policy, None).is_ok();
        assert_eq!(allowed, expect_auto, "{label}");
    }
    Ok(())
}

#[test]
fn gate_evaluator_source_trust_respects_sensitivity_ceiling() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    put_policy_manifest_bytes(&vault, test_id(0x75), &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::ToolOutput,
        PolicyCriticality::Normal,
    );

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    input.sensitivity_band = Some(1);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    input.sensitivity_band = None;
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    Ok(())
}

#[test]
fn gate_evaluator_generated_source_requires_explicit_auto_permit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
        ClaimSource::Generated,
        0,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x76), &data)?;
    let policy = resolve(&vault)?;

    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::Generated,
        PolicyCriticality::Normal,
    );
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    put_policy_manifest_bytes(&vault, test_id(0x77), &data)?;
    let policy = resolve(&vault)?;
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    Ok(())
}

#[test]
fn gate_evaluator_content_kind_reasons_are_stable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x73), &data)?;
    let policy = resolve(&vault)?;

    let mut edge_provenance = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    edge_provenance.content_kind = GateContentKind::EdgeProvenanceClaim;
    assert_eq!(
        edge_provenance.content_kind.as_str(),
        "edge_provenance_claim"
    );
    let decision = policy.evaluate_gate(&edge_provenance);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    let mut policy_manifest = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    policy_manifest.content_kind = GateContentKind::PolicyManifest;
    assert_eq!(policy_manifest.content_kind.as_str(), "policy_manifest");
    let decision = policy.evaluate_gate(&policy_manifest);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.policy_manifest_authority"]
    );

    let mut external_effect = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    external_effect.content_kind = GateContentKind::ExternalEffect;
    assert_eq!(external_effect.content_kind.as_str(), "external_effect");
    let decision = policy.evaluate_gate(&external_effect);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(decision.outcome().as_str(), "pending");

    Ok(())
}
