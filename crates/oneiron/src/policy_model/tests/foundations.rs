//! Engine ships no policy: defaults, inactive planes, manifest compat, warn byte-identity.

use super::*;
use crate::error::RelayError;

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
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_output_contract",
                reason
            }) if reason.contains("document")
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
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_output_contract",
                reason: "names a contract the engine does not have"
            })
        ),
        "unexpected error: {err}"
    );
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
