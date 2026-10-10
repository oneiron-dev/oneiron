//! Gate evaluator core: fail-closed default, criticality matrix, reason codes, and metrics.

use super::*;

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
