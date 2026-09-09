//! Classifier dial and pattern roles: verdict reuse per dial/mode, model-call economy, strictest-role-wins.

use super::*;

#[test]
fn a_verdict_minted_under_pattern_gated_goes_stale_when_the_dial_says_classify_all() -> Result<()> {
    // The release direction: content the old dial waved through without a
    // model must not stay waved through once the config says a model looks at
    // everything.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x86), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let gated = owner_dial(RelayClassifierMode::PatternGated);

    let verdict = vault.classify_policy_model_with_config(request.clone(), &gated)?;
    assert_eq!(
        verdict.classifier_mode,
        Some(RelayClassifierMode::PatternGated),
        "the verdict records the dial that governed its minting plane"
    );
    assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &gated)?);

    assert!(vault.policy_model_verdict_is_stale_with_config(
        &verdict,
        &request,
        &owner_dial(RelayClassifierMode::ClassifyAll),
    )?);
    Ok(())
}

#[test]
fn a_verdict_minted_under_classify_all_goes_stale_when_the_dial_says_pattern_gated() -> Result<()> {
    // The sovereignty direction, and the worse of the two: a rule the owner
    // effectively switched off must stop being enforced.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x87), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
    let all = owner_dial(RelayClassifierMode::ClassifyAll);

    let verdict = vault.classify_policy_model_with_config(request.clone(), &all)?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.classifier_mode,
        Some(RelayClassifierMode::ClassifyAll)
    );
    assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &all)?);

    assert!(vault.policy_model_verdict_is_stale_with_config(
        &verdict,
        &request,
        &owner_dial(RelayClassifierMode::PatternGated),
    )?);
    Ok(())
}

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

    assert!(matches!(refused, Err(Error::PolicyVerdictNotInForce)));
    Ok(())
}

#[test]
fn a_hosted_dial_flip_never_stales_an_owner_verdict() -> Result<()> {
    // The whole point of the two dials: the planes answer different questions,
    // so one plane's configuration moving says nothing about the other's
    // verdicts.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x8a), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
    let verdict = vault.classify_policy_model_with_config(
        request.clone(),
        &owner_dial(RelayClassifierMode::ClassifyAll),
    )?;

    let hosted_flipped = PolicyModelConfig {
        owner_classifier_mode: RelayClassifierMode::ClassifyAll,
        hosted_classifier_mode: RelayClassifierMode::PatternGated,
        ..PolicyModelConfig::default()
    };

    assert!(!vault.policy_model_verdict_is_stale_with_config(
        &verdict,
        &request,
        &hosted_flipped
    )?);
    Ok(())
}

#[test]
fn a_dial_flip_on_a_disabled_plane_leaves_its_inert_clean_allow_fresh() -> Result<()> {
    // A plane that is OFF decided nothing, so nothing about the classifier can
    // invalidate its clean allow — reporting it stale would only send the
    // caller to re-derive its way back to the identical verdict. The dial is
    // asked of a LIVE plane, beside the frontier, and of nothing else.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let verdict = vault.classify_policy_model_with_config(
        request.clone(),
        &owner_dial(RelayClassifierMode::PatternGated),
    )?;
    assert!(verdict.is_inert_clean_allow());

    assert!(!vault.policy_model_verdict_is_stale_with_config(
        &verdict,
        &request,
        &owner_dial(RelayClassifierMode::ClassifyAll),
    )?);
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
fn a_hosted_attestation_stops_attesting_once_the_hosted_dial_moves() -> Result<()> {
    // The version and hash say WHICH policy was in force. They say nothing
    // about how hard the pass was told to look at it, so a receipt from the
    // old dial names the right policy and still is not evidence for the new
    // one. Same bug class the owner dial had; same answer.
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let policy = registered_policy(&registry);
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let minted_under = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &minted_under)?;
    let receipt =
        PolicyClassifyVerdict::clean_allow(binding, &minted_under, PolicyPlane::OwnerPolicy)
            .attesting_hosted_plane(&policy, &minted_under, &answered_pass());

    assert!(receipt.attests_hosted_plane(&policy, &minted_under));
    assert!(
        !receipt.attests_hosted_plane(
            &policy,
            &PolicyModelConfig {
                hosted_classifier_mode: RelayClassifierMode::PatternGated,
                ..PolicyModelConfig::default()
            },
        ),
        "the same policy under a different dial is a different question"
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
fn a_hosted_dial_flip_leaves_a_vault_side_receipt_trusted() -> Result<()> {
    // The cross-plane pin at the same door: the receipt records a vault-side
    // pass, so the hosted dial has nothing to say about it.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &config)?;
    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        binding.content_hash,
        PolicyClassifyVerdict::clean_allow(binding, &config, PolicyPlane::OwnerPolicy),
    );

    let pass = block_on(vault.relay_boundary_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        None,
        &verdicts,
    ))?;

    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    Ok(())
}

#[test]
fn owner_plane_pattern_gated_skips_the_model_when_nothing_escalates() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x76), &owner_manifest_with_decide_pattern())?;
    let backend = CountingPolicyBackend::clean();
    let config = PolicyModelConfig {
        owner_classifier_mode: RelayClassifierMode::PatternGated,
        ..PolicyModelConfig::default()
    };

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        &config,
        &backend,
        &lease("owner-gated-miss"),
    ))?;

    assert_eq!(
        backend.calls(),
        0,
        "nothing escalated, so nothing was asked"
    );
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    Ok(())
}

#[test]
fn owner_plane_pattern_gated_still_short_circuits_on_a_decide_hit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x77), &owner_manifest_with_decide_pattern())?;
    let backend = CountingPolicyBackend::clean();
    let config = PolicyModelConfig {
        owner_classifier_mode: RelayClassifierMode::PatternGated,
        ..PolicyModelConfig::default()
    };

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &config,
        &backend,
        &lease("owner-gated-decide"),
    ))?;

    // The hard rule the owner wrote is the verdict, and it is reached BEFORE
    // the dial is consulted at all — gating never softens a `Decide`.
    assert_eq!(backend.calls(), 0);
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    Ok(())
}

#[test]
fn the_hosted_dial_never_gates_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x78), &owner_manifest_with_decide_pattern())?;
    let backend = CountingPolicyBackend::clean();
    // Hosted gated, owner not. Content matches no pattern, so a plane reading
    // the WRONG dial would skip the model.
    let config = PolicyModelConfig {
        owner_classifier_mode: RelayClassifierMode::ClassifyAll,
        hosted_classifier_mode: RelayClassifierMode::PatternGated,
        ..PolicyModelConfig::default()
    };

    block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        &config,
        &backend,
        &lease("owner-reads-owner-dial"),
    ))?;

    assert_eq!(
        backend.calls(),
        1,
        "the owner plane is `ClassifyAll`; the hosted dial is not its business"
    );
    Ok(())
}

#[test]
fn the_owner_dial_never_gates_the_hosted_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let backend = CountingPolicyBackend::clean();
    // Owner gated, hosted not. The hosted policy carries no patterns at all,
    // so a plane reading the WRONG dial would skip the model.
    let config = PolicyModelConfig {
        owner_classifier_mode: RelayClassifierMode::PatternGated,
        hosted_classifier_mode: RelayClassifierMode::ClassifyAll,
        ..PolicyModelConfig::default()
    };

    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&backend, &lease("hosted-reads-hosted-dial"))),
    )?;

    assert_eq!(
        backend.calls(),
        1,
        "the hosted plane is `ClassifyAll`; the owner dial is not its business"
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));
    Ok(())
}

#[test]
fn classify_all_sends_every_item_to_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let backend = CountingPolicyBackend::clean();
    let budget = lease("classify-all");
    for content in [BOMB_CONTENT, CLEAN_CONTENT, "a third unrelated line"] {
        relay_pass(
            &vault,
            content,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
    }
    assert_eq!(backend.calls(), 3, "ClassifyAll classifies 100% of content");
    Ok(())
}

#[test]
fn an_escalate_hit_buys_exactly_one_model_call_and_the_model_wins() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![escalate_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("escalate");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 1);
    // The model overruled the pattern, and the pattern did not get a vote.
    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));

    // ... and the overruled hit is STILL receipted. That row is the whole
    // reason a substrate owner can find out their pattern is too wide.
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1, "an overruled escalate is receipted");
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.hosted.bomb"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_role.escalate"
    ));
    assert_eq!(receipts[0].outcome, "relay_boundary_allow");
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

#[test]
fn a_log_only_hit_allows_calls_no_model_and_is_receipted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![log_rule(
        "hosted.watchlist",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("log-only");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "a log rule never triggers the model");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::LogOnly));
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(has_trace(&receipts[0], "gate.relay.resolution.log_only"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.hosted.watchlist"
    ));
    Ok(())
}

#[test]
fn pattern_gated_with_no_hit_allows_with_zero_model_calls_and_its_own_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![escalate_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("gated-miss");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternGatedAllow));
    let receipts = gate_receipts(&vault)?;
    assert_eq!(
        receipts.len(),
        1,
        "an allow nothing examined is a distinct fact, and is recorded"
    );
    assert!(has_trace(
        &receipts[0],
        "gate.relay.resolution.pattern_gated_allow"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.relay.classifier_mode.pattern_gated"
    ));
    Ok(())
}

#[test]
fn the_strictest_matching_role_acts_and_every_id_is_receipted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // All three roles match the same content. `Decide` is strictest, so it
    // acts — and the other two are still named in the receipt.
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![
        log_rule("hosted.log", "(?i)bomb"),
        escalate_rule("hosted.escalate", "(?i)build"),
        decide_rule("hosted.decide", "(?i)explain"),
    ]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("precedence");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "Decide short-circuits the model");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.matched_pattern_ids,
        vec![
            "hosted.log".to_owned(),
            "hosted.escalate".to_owned(),
            "hosted.decide".to_owned()
        ]
    );
    assert_eq!(audit.acting_pattern_role, Some(PolicyPatternRole::Decide));
    let receipts = gate_receipts(&vault)?;
    for id in ["hosted.log", "hosted.escalate", "hosted.decide"] {
        assert!(
            has_trace(
                &receipts[0],
                &format!("gate.policy_model.pattern_matched.{id}")
            ),
            "missing matched id {id}"
        );
    }
    Ok(())
}

#[test]
fn ties_on_strictness_resolve_to_the_rule_written_first() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Two rules of equal strictness, resolving to DIFFERENT rows: the row the
    // verdict names is what says which of them acted.
    let registry = hosted_edge_registry(hosted_two_row_policy(vec![
        decide_rule("hosted.first", "(?i)bomb"),
        decide_rule_for("hosted.second", "(?i)build", HOSTED_SELF_HARM_LABEL),
    ]));
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        None,
    )?;
    let verdict = pass.boundary_verdict().expect("verdict");
    let audit = verdict.audit.as_deref().expect("audit");
    assert_eq!(
        audit.matched_pattern_ids,
        vec!["hosted.first".to_owned(), "hosted.second".to_owned()]
    );
    assert!(
        matches!(
            verdict.category,
            PolicyVerdictCategory::HostedLegal { ref row_ref, .. }
                if row_ref == "hosted:serious-crime"
        ),
        "the rule written first must win the tie, got {:?}",
        verdict.category
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternDecided));
    Ok(())
}
