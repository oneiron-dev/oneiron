//! Classifier dial and pattern roles: verdict reuse per dial/mode, model-call economy, strictest-role-wins.

use super::*;
use crate::error::RelayError;

#[test]
fn a_verdict_carrying_no_recorded_dial_reads_stale() -> Result<()> {
    // The compat case, decoded the way a verdict persisted before the field
    // existed decodes. It must FAIL CLOSED: reading an absent dial as "well,
    // probably the default" is a compat gap that releases content.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x88), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
    let config = PolicyModelConfig::default();

    let fresh = vault.classify_policy_model_with_config(request.clone(), &config)?;
    let mut wire = serde_json::to_value(&fresh).expect("verdict serializes");
    wire.as_object_mut()
        .expect("verdict is a JSON object")
        .remove("classifier_mode")
        .expect("a fresh verdict carries the field");
    let old: PolicyClassifyVerdict = serde_json::from_value(wire).expect("old verdicts decode");

    assert_eq!(old.classifier_mode, None);
    assert!(
        vault.policy_model_verdict_is_stale_with_config(&old, &request, &config)?,
        "an unrecorded dial is not a matching dial"
    );
    Ok(())
}

#[test]
fn the_enforce_door_refuses_a_verdict_whose_dial_moved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x89), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
    let verdict = vault.classify_policy_model_with_config(
        request.clone(),
        &owner_dial(RelayClassifierMode::ClassifyAll),
    )?;

    let refused = vault.enforce_policy_model_verdict(
        request,
        &owner_dial(RelayClassifierMode::PatternGated),
        verdict,
        false,
    );

    assert!(matches!(
        refused,
        Err(Error::Relay(RelayError::PolicyVerdictNotInForce))
    ));
    Ok(())
}

#[test]
fn a_vault_side_receipt_whose_dial_moved_is_not_trusted() -> Result<()> {
    // The third reuse door. A relay trusts a vault-side receipt only while the
    // configuration that produced it is the configuration in force, and the
    // dial is part of that — the same rule the safeguard-selector check beside
    // it already applies.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let minted_under = owner_dial(RelayClassifierMode::ClassifyAll);
    let binding = vault.relay_verify_binding(&request, &minted_under)?;
    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        binding.content_hash,
        PolicyClassifyVerdict::clean_allow(binding, &minted_under, PolicyPlane::OwnerPolicy),
    );

    let pass = block_on(vault.relay_boundary_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &owner_dial(RelayClassifierMode::PatternGated),
        None,
        &verdicts,
    ))?;

    assert!(
        pass.ran_relay_classify(),
        "an untrusted receipt falls through to the hosted pass"
    );
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts.iter().any(|receipt| has_trace(
            receipt,
            "gate.relay.vault_receipt_untrusted.classifier_mode_mismatch"
        )),
        "the breach names itself in the ledger",
    );
    Ok(())
}

#[test]
fn an_attestation_recording_no_hosted_dial_attests_nothing() -> Result<()> {
    // The compat case, decoded the way an attestation written before the field
    // existed decodes. It must read as NOT attesting: a redundant hosted pass
    // costs a model call, a wrongly trusted one costs the coverage.
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let policy = registered_policy(&registry);
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &config)?;
    let fresh = PolicyClassifyVerdict::clean_allow(binding, &config, PolicyPlane::OwnerPolicy)
        .attesting_hosted_plane(&policy, &config, &answered_pass());

    let mut wire = serde_json::to_value(&fresh).expect("verdict serializes");
    wire.get_mut("hosted_attestation")
        .and_then(serde_json::Value::as_object_mut)
        .expect("a fresh attestation is an object")
        .remove("classifier_mode")
        .expect("a fresh attestation carries the field");
    let old: PolicyClassifyVerdict = serde_json::from_value(wire).expect("old receipts decode");

    assert_eq!(
        old.hosted_attestation
            .as_ref()
            .expect("attestation survives")
            .classifier_mode,
        None
    );
    assert!(
        !old.attests_hosted_plane(&policy, &config),
        "an unrecorded dial is not a matching dial"
    );
    Ok(())
}

#[test]
fn a_hosted_dial_flip_sends_an_attested_receipt_back_through_the_hosted_pass() -> Result<()> {
    // End to end at the trust door: with a hosted policy bound, a receipt whose
    // hosted dial no longer matches is not evidence the hosted plane ran, so
    // the relay runs it rather than trusting the receipt.
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let policy = registered_policy(&registry);
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let minted_under = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &minted_under)?;
    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        binding.content_hash,
        PolicyClassifyVerdict::clean_allow(binding, &minted_under, PolicyPlane::OwnerPolicy)
            .attesting_hosted_plane(&policy, &minted_under, &answered_pass()),
    );
    let backend = clean_backend();
    let budget = lease("hosted-dial-attestation");

    let pass = block_on(vault.relay_boundary_pass(
        request,
        &cloud_witness(),
        &registry,
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
        &verdicts,
    ))?;

    assert!(
        pass.ran_relay_classify(),
        "an unattested receipt falls through to the hosted pass"
    );
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts.iter().any(|receipt| has_trace(
            receipt,
            "gate.relay.vault_receipt_untrusted.hosted_plane_unattested"
        )),
        "and the breach names itself in the ledger",
    );
    Ok(())
}

#[test]
fn a_decide_hit_is_the_verdict_and_calls_no_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![decide_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("decide");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "a hard rule needs no model");
    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::HostedLegal {
            category: "serious_crime".to_owned(),
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:serious-crime".to_owned(),
        }
    );
    assert!(pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternDecided));
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.resolution.pattern_decided"
    ));
    Ok(())
}
