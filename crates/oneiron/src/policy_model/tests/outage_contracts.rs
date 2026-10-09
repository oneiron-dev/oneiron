//! Outage behaviour per mode and host posture, output-contract presets, rationale fields.

use super::*;

#[test]
fn a_hosted_pass_with_no_model_tier_degrades_and_halts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        None,
    )?;
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelTierAbsent)
    );
    assert!(
        pass.must_halt_relay(),
        "the hosted plane is fail-closed: an unanswered policy stops the relay"
    );
    Ok(())
}

#[test]
fn an_unreadable_answer_is_a_classification_failure_not_an_allow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let budget = lease("unreadable");
    for body in [
        "not json at all",
        r#"{"violation":2,"policy_category":null}"#,
        r#"{"violation":1,"policy_category":null}"#,
        r#"{"violation":1,"policy_category":"hosted_legal/ncii"}"#,
        r#"{"violation":0,"policy_category":"hosted_legal/serious_crime"}"#,
        r#"{"violation":0,"policy_category":null,"extra":"field"}"#,
    ] {
        let backend = static_backend(body);
        let pass = relay_pass(
            &vault,
            CLEAN_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
        assert_eq!(
            pass.degraded(),
            Some(RelayBoundaryDegrade::SafeguardModelResponseUnusable),
            "body: {body}"
        );
        assert!(pass.must_halt_relay(), "body: {body}");
    }
    Ok(())
}

#[test]
fn the_owner_plane_fails_open_where_the_hosted_plane_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x4a),
        &documented_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            Vec::new(),
        ),
    )?;
    // The same unreadable answer, on the two planes. The owner's plane ships
    // the content; the hosted plane stops the relay.
    let backend = static_backend("not json at all");
    let owner = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(CLEAN_CONTENT),
        &PolicyModelConfig::default(),
        &backend,
        &lease("owner-fails-open"),
    ))?;
    assert_eq!(owner.decision, PolicyClassifyDecision::Allow);

    let budget = lease("hosted-fails-closed");
    let hosted = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert!(hosted.must_halt_relay());
    Ok(())
}

#[test]
fn an_availability_degrade_halts_under_the_default_outage_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let budget = lease("outage-halt");
    let config = PolicyModelConfig {
        hosted_outage_policy: HostedOutagePolicy::Halt,
        ..PolicyModelConfig::default()
    };
    assert_eq!(
        PolicyModelConfig::default().hosted_outage_policy,
        HostedOutagePolicy::Halt,
        "fail-closed stays the default a host gets without asking"
    );

    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;

    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    assert!(pass.must_halt_relay());
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degrade_halted")),
        "the ledger says what the relay actually did about the degrade",
    );
    Ok(())
}

#[test]
fn an_unattestable_verdict_halts_even_under_proceed_receipted() -> Result<()> {
    // The knob is about AVAILABILITY. A verdict that cannot be pinned to the
    // policy state it was decided against is not an outage — the model may
    // well have answered, twice — and the hosted plane never relays on a
    // verdict it cannot attest, whatever the host's posture.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("unattestable-proceed");
    let config = PolicyModelConfig {
        hosted_outage_policy: HostedOutagePolicy::ProceedReceipted,
        ..PolicyModelConfig::default()
    };

    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &config,
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    assert!(!RelayBoundaryDegrade::PolicyBindingMovedMidPass.is_model_availability());
    assert!(pass.must_halt_relay());
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degrade_halted")),
    );
    Ok(())
}

#[test]
fn every_output_contract_round_trips_through_the_relay() -> Result<()> {
    let budget = lease("contracts");
    for (contract, clean, violating) in [
        (PolicyOutputContract::Binary, "0", "1"),
        (
            PolicyOutputContract::CategoryJson,
            r#"{"violation":0,"policy_category":null}"#,
            r#"{"violation":1,"policy_category":"hosted_legal/serious_crime"}"#,
        ),
        (
            PolicyOutputContract::RationaleJson,
            r#"{"violation":0,"policy_category":null,"rule_ids":[],"confidence":"high","rationale":"nothing in this text is instructional"}"#,
            r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["SC-1"],"confidence":"high","rationale":"actionable instruction"}"#,
        ),
    ] {
        let policy = HostedLegalPolicy {
            output_contract: Some(contract),
            ..hosted_serious_crime_block()
        };
        let registry = hosted_edge_registry(policy);

        let (_tmp, vault) = temp_vault();
        let clean_backend = static_backend(clean);
        let clean_pass = relay_pass(
            &vault,
            CLEAN_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&clean_backend, &budget)),
        )?;
        assert_eq!(
            clean_pass.boundary_verdict().expect("verdict").decision,
            PolicyClassifyDecision::Allow,
            "contract: {contract:?}"
        );
        assert!(clean_pass.degraded().is_none(), "contract: {contract:?}");

        let (_tmp, vault) = temp_vault();
        let violating_backend = static_backend(violating);
        let violating_pass = relay_pass(
            &vault,
            BOMB_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&violating_backend, &budget)),
        )?;
        assert_eq!(
            violating_pass.boundary_verdict().expect("verdict").decision,
            PolicyClassifyDecision::Block,
            "contract: {contract:?}"
        );
        assert!(violating_pass.must_halt_relay(), "contract: {contract:?}");
    }
    Ok(())
}

#[test]
fn rationale_fields_land_in_the_verdict_and_the_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["serious_crime","hosted:serious-crime","nope","nope"],"confidence":"high","rationale":"the text gives step-by-step instructions"}"#,
    );
    let budget = lease("rationale");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    // Both spellings resolve to the same ROW — the category label the model
    // was shown and the `row_ref` a reader is pointed at — so they collapse to
    // ONE citation, kept under the model's first spelling. This assertion used
    // to expect both, which counted one rule twice in the audit.
    assert_eq!(audit.model_rule_ids, vec!["serious_crime".to_owned()]);
    // And the two identical junk ids are one thing the model got wrong, not
    // two, for the same reason a repeated valid citation is one citation.
    assert_eq!(audit.model_rule_ids_dropped, 1);
    assert_eq!(audit.model_confidence.as_deref(), Some("high"));
    assert_eq!(
        audit.model_rationale.as_deref(),
        Some("the text gives step-by-step instructions")
    );

    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_rule.serious_crime"
    ));
    // ONE trace code for the row, not one per spelling. A reader counting
    // `model_rule.*` codes is counting rules the model cited, and the second
    // spelling would have made one row look like two.
    assert!(
        !has_trace(
            &receipts[0],
            "gate.policy_model.model_rule.hosted_serious-crime"
        ),
        "the second spelling of the same row does not earn its own code"
    );
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_confidence.high"
    ));
    Ok(())
}
