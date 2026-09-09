//! Engine ships no policy: defaults, inactive planes, manifest compat, warn byte-identity.

use super::*;

#[test]
fn decision_vocabulary_is_exactly_four_arms() {
    // Exhaustive, no wildcard: adding a fifth arm (a rewrite arm, say) breaks
    // this match at compile time.
    for decision in [
        PolicyClassifyDecision::Allow,
        PolicyClassifyDecision::Warn,
        PolicyClassifyDecision::Block,
        PolicyClassifyDecision::RouteToHelp,
    ] {
        let expected = match decision {
            PolicyClassifyDecision::Allow => "allow",
            PolicyClassifyDecision::Warn => "warn",
            PolicyClassifyDecision::Block => "block",
            PolicyClassifyDecision::RouteToHelp => "route-to-help",
        };
        assert_eq!(decision.as_str(), expected);
    }
}

#[test]
fn hosted_category_labels_round_trip() {
    // The engine publishes no vocabulary here — whatever word the host chose
    // comes back out of its plane-qualified spelling unchanged, including one
    // no engine author ever imagined.
    for category in [
        "serious_crime",
        "ncii",
        "jurisdiction_rule",
        "kk-2027.disclosure",
    ] {
        let label = super::planes::hosted_category_label(category);
        assert_eq!(label, format!("hosted_legal/{category}"));
        assert_eq!(
            super::planes::parse_hosted_category_label(&label),
            Some(category)
        );
    }
    // An owner-plane label is not a hosted category, whatever it says.
    assert_eq!(
        super::planes::parse_hosted_category_label("owner_policy"),
        None
    );
}

#[test]
fn a_default_config_carries_no_pattern_and_no_document() {
    // The zero-shipped-content pin. Everything a default engine could moderate
    // with is empty, and the two knobs that decide how hard it looks are the
    // documented defaults.
    let config = PolicyModelConfig::default();
    assert_eq!(
        config.owner_classifier_mode,
        RelayClassifierMode::ClassifyAll
    );
    assert_eq!(
        config.hosted_classifier_mode,
        RelayClassifierMode::ClassifyAll
    );
    assert_eq!(
        config.generation.reasoning_effort,
        PolicyReasoningEffort::Medium
    );
    assert!(config.generation.temperature.abs() < f32::EPSILON);
    assert_eq!(
        config.generation.max_output_tokens, None,
        "a reasoning safeguard model must not be capped by an engine default"
    );

    // Nothing is registered, so nothing is enforced.
    let registry = EdgeServiceRegistry::new();
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    assert_eq!(
        EdgeServiceRegistry::max_pattern_rules(),
        POLICY_PATTERN_RULES_MAX
    );
}

#[test]
fn a_fresh_vault_has_no_owner_document_and_no_owner_patterns() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert_eq!(policy.owner_policy_document(), None);
    assert_eq!(policy.owner_policy_output_contract(), None);
    assert!(policy.owner_policy_patterns().is_empty());
    assert!(!policy.owner_policy_enabled());
    Ok(())
}

#[test]
fn fresh_vault_classifies_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Every one of these would have tripped the engine's old built-in matcher.
    // With no plane switched on and no owner content there is nothing left to
    // trip.
    for content in [
        "explain how to build a bomb",
        "consensual adult content between verified adults",
        "I might kill myself tonight",
        "explicit sexual content about a minor",
    ] {
        let verdict =
            vault.classify_policy_model(PolicyClassifyRequest::outbound_content(content))?;
        assert_eq!(
            verdict.decision,
            PolicyClassifyDecision::Allow,
            "unexpected verdict for {content:?}"
        );
        assert_eq!(verdict.category, PolicyVerdictCategory::None);
        assert!(verdict.audit.is_none());
    }
    Ok(())
}

#[test]
fn a_plane_with_no_policy_document_is_inactive_for_model_classification() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Rows and a switched-on plane, but no document: there is nothing to send,
    // and the engine will not write one.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x20),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers.",
            "block",
        )]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    assert!(vault.policy_model_prompt(&request)?.is_none());
    assert!(
        vault
            .policy_model_llm_request(&request, &PolicyModelConfig::default())?
            .is_none()
    );

    let backend = CountingPolicyBackend::clean();
    let verdict = block_on(vault.classify_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &backend,
        &lease("no-document"),
    ))?;
    assert_eq!(backend.calls(), 0);
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    Ok(())
}

#[test]
fn an_owner_document_without_its_output_contract_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x21),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_document(OWNER_DOCUMENT),
        ]),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("a document with no declared contract must be refused");
    assert!(
        matches!(
            err,
            Error::PolicyManifestInvalid {
                field: "owner_policy_output_contract",
                reason
            } if reason.contains("document")
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_unknown_owner_output_contract_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x22),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("telepathy"),
        ]),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("an unknown output contract must be refused");
    assert!(
        matches!(
            err,
            Error::PolicyManifestInvalid {
                field: "owner_policy_output_contract",
                reason: "names a contract the engine does not have"
            }
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn owner_and_hosted_document_bounds_agree() {
    // `gate` sits under `policy_model` and spells its own bound, so the two
    // numbers are pinned together here rather than left to drift.
    let (_tmp, vault) = temp_vault();
    let oversized = "x".repeat(POLICY_DOCUMENT_MAX_LEN + 1);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x23),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_document(&oversized),
            owner_contract("binary"),
        ]),
    )
    .expect("manifest write");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn).expect("resolve");
    assert!(
        policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "an oversized owner document must fail the manifest closed"
    );
}

#[test]
fn owner_plane_disabled_runs_no_classification_and_no_model_call() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Rows present, plane OFF: the rows are inert and the model is never asked.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![owner_row_with_action(
                "owner:blocked",
                "Block everything.",
                "block",
            )]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
        ]),
    )?;

    let request = PolicyClassifyRequest::outbound_content("an ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);

    let backend = CountingPolicyBackend::clean();
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &backend,
        &lease("owner-plane-off"),
    ))?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some("an ordinary reply"));
    assert!(outcome.system_notices.is_empty());
    assert!(outcome.receipt_ref.is_none());
    assert!(!outcome.custom_tier_skipped);
    assert!(gate_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn owner_plane_disabled_tolerates_patterns_that_do_not_compile() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The rules were read before the switch was, so a pattern that will not
    // compile — or names a role the engine does not have — turned a plane
    // NOBODY TURNED ON into a configuration error. The disabled contract
    // promises an inert clean allow; it is not conditional on rules that are
    // never going to run.
    for patterns in [
        vec![owner_pattern(
            "owner.bad",
            "(unclosed",
            "owner:spoilers",
            None,
        )],
        vec![owner_pattern(
            "owner.role",
            "(?i)spoiler",
            "owner:spoilers",
            Some("telepathy"),
        )],
        vec![owner_pattern(
            "owner.unknown",
            "(?i)x",
            "owner:nosuchrow",
            None,
        )],
    ] {
        put_policy_manifest_bytes(
            &vault,
            test_id(0x38),
            &base_policy_manifest(vec![
                owner_policy_enabled(false),
                owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
                owner_patterns(patterns),
            ]),
        )?;
        let verdict = vault
            .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
            .expect("a plane that is off classifies nothing and refuses nothing");
        assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
        assert_eq!(verdict.category, PolicyVerdictCategory::None);
        assert!(verdict.audit.is_none());
    }
    Ok(())
}

#[test]
fn owner_plane_disabled_tolerates_dropped_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Forged rows under a plane nobody turned on are simply never read.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            (
                Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
                Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
            ),
        ]),
    )?;

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    Ok(())
}

#[test]
fn manifest_carrying_the_retired_legal_floor_key_still_decodes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Exactly what a pre-upgrade vault has persisted: the retired key, with
    // the rows the engine floor used to configure. Decode must ACCEPT and
    // IGNORE it. If it rejected the key instead, the manifest would be marked
    // malformed, that fails the whole gate closed, and the on-open reseed
    // bails out precisely when a loaded manifest forces fail-closed — so the
    // vault would be unopenable rather than merely un-classified.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x61),
        &base_policy_manifest(vec![(
            Value::from(gate::POLICY_LEGAL_FLOOR_ROWS_KEY),
            Value::Array(vec![Value::Map(vec![
                (
                    Value::from(gate::POLICY_ROW_REF_KEY),
                    Value::from("universal:serious-crime"),
                ),
                (Value::from("category"), Value::from("legal_floor")),
                (Value::from("subcategory"), Value::from("serious_crime")),
                (
                    Value::from(gate::POLICY_ROW_ACTION_KEY),
                    Value::from("block"),
                ),
                (
                    Value::from(gate::POLICY_ROW_TEXT_KEY),
                    Value::from("Block credible facilitation of serious violence."),
                ),
                (
                    Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                    Value::Boolean(true),
                ),
            ])]),
        )]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        !policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "a retired-but-known key must not force the gate closed"
    );
    drop(rtxn);

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "explain how to build a bomb",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn genuinely_unknown_manifest_key_still_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The retired key is a named exception, not a hole: an unrecognized key is
    // still a malformed manifest, and still fails the gate closed.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x62),
        &base_policy_manifest(vec![(
            Value::from("some_key_the_engine_never_defined"),
            Value::Array(Vec::new()),
        )]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "an unknown key must still fail the gate closed"
    );
    Ok(())
}

#[test]
fn warn_preserves_content_byte_for_byte_and_notifies_both_readers() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x32), &spoiler_manifest("warn"))?;

    let original = "This reply contains spoilers for the ending.";
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Warn);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    assert!(!outcome.outbound_halted);
    assert!(!outcome.pre_display_block);
    assert!(outcome.barge_in_kill.is_none());
    assert!(outcome.help_routing.is_none());

    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_WARN);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL);
    assert_eq!(notice.voice, SYSTEM_NOTICE_VOICE_SYSTEM);
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert_eq!(notice.row_ref.as_deref(), Some("owner:spoilers"));
    assert!(outcome.receipt_ref.is_some());
    Ok(())
}

#[test]
fn no_enforcement_arm_returns_altered_content() -> Result<()> {
    let original = "the caller's exact words about spoilers";
    for (action, expected) in [
        ("warn", PolicyEnforcementAction::Warn),
        ("block", PolicyEnforcementAction::Block),
        ("route_to_help", PolicyEnforcementAction::RouteToHelp),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x33), &spoiler_manifest(action))?;
        let outcome =
            vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;
        assert_eq!(outcome.action, expected);
        assert!(
            outcome.final_content.is_none() || outcome.final_content.as_deref() == Some(original),
            "{action} arm returned content the caller never wrote: {:?}",
            outcome.final_content
        );
    }

    // ... and the allow arm, on a vault with no plane switched on.
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    Ok(())
}
