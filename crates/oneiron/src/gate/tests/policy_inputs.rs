//! Policy-input primitives: companion access grants, budget-exhaustion parsing, and ceiling math.

use super::*;

#[test]
fn companion_profile_access_grants_allow_deny_and_revoke() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // 0x71: [0xA1; 16] is a write-door-reserved system-agent actor id (ONE-1444).
    let grant_id = test_id(0x71);
    let principal = test_id(0xB1);
    let other_principal = test_id(0xB3);
    let person = test_id(0xC1);
    let persona = test_id(0xD1);
    let other_persona = test_id(0xD2);

    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None,
        "missing grant must fail closed"
    );

    let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
    vault.create_access_grant(&grant_id, &grant)?;

    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        Some(grant_id),
        "exact active grant should authorize"
    );
    assert_eq!(
        vault.companion_profile_access_grant(&other_principal, &person, &persona)?,
        None,
        "principal mismatch must deny"
    );
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &other_persona)?,
        None,
        "scope mismatch must deny"
    );

    let revoked = vault.revoke_access_grant(&grant_id, 20)?;
    assert_eq!(
        revoked.status,
        crate::access_grant::AccessGrantStatus::Revoked
    );
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None,
        "revoked grant must fail closed"
    );
    Ok(())
}

#[test]
fn companion_profile_access_grant_fails_closed_on_malformed_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let malformed_id = test_id(0x01);
    // 0x72: [0xA2; 16] is a write-door-reserved system-agent actor id (ONE-1444).
    let valid_id = test_id(0x72);
    let principal = test_id(0xB2);
    let person = test_id(0xC2);
    let persona = test_id(0xD3);

    put_malformed_access_grant_bytes(&vault, &malformed_id, b"not-msgpack")?;
    let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
    vault.create_access_grant(&valid_id, &grant)?;

    let err = vault
        .companion_profile_access_grant(&principal, &person, &persona)
        .expect_err("malformed AccessGrant row must fail closed before any later allow");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex for malformed AccessGrant row, got {err:?}"
    );
    Ok(())
}

#[test]
fn policy_manifest_budget_exhaustion_defaults_to_suspend() -> Result<()> {
    assert_eq!(
        PolicyManifestResolution::default().on_budget_exhausted(),
        BudgetExhaustionPolicy::Suspend
    );

    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x81), &encode_policy_manifest(vec![]))?;

    let policy = resolve(&vault)?;
    assert_eq!(
        policy.on_budget_exhausted(),
        BudgetExhaustionPolicy::Suspend
    );
    Ok(())
}

#[test]
fn policy_manifest_budget_exhaustion_parses_continue_and_overdraft() -> Result<()> {
    let (_tmp, continue_vault) = temp_vault();
    let continue_manifest = encode_policy_manifest(vec![(
        Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
        Value::from("continue_on_local"),
    )]);
    put_policy_manifest_bytes(&continue_vault, test_id(0x82), &continue_manifest)?;
    assert_eq!(
        resolve(&continue_vault)?.on_budget_exhausted(),
        BudgetExhaustionPolicy::ContinueOnLocal
    );

    let (_tmp, overdraft_vault) = temp_vault();
    let overdraft_manifest = encode_policy_manifest(vec![(
        Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
        Value::Map(vec![
            (Value::from("kind"), Value::from("overdraft")),
            (Value::from("cap"), Value::from(25_u64)),
        ]),
    )]);
    put_policy_manifest_bytes(&overdraft_vault, test_id(0x83), &overdraft_manifest)?;
    assert_eq!(
        resolve(&overdraft_vault)?.on_budget_exhausted(),
        BudgetExhaustionPolicy::Overdraft { cap: 25 }
    );
    Ok(())
}

#[test]
fn conflicting_budget_exhaustion_policies_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x84),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("continue_on_local"),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x85),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("suspend"),
        )]),
    )?;

    let policy = resolve(&vault)?;
    assert!(policy.diagnostics().malformed_manifest_seen);
    assert!(policy.is_fail_closed());
    Ok(())
}

#[test]
fn min_of_two_caps() {
    for (confirmed_scope, introducer_ceiling, expected) in [
        (
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto,
        ),
        (
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
        ),
        (
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
        ),
        (
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
        ),
    ] {
        assert_eq!(
            foreign_agent_effective_ceiling(confirmed_scope, introducer_ceiling),
            expected
        );
    }
}

#[test]
fn introducer_lower_wins() {
    assert_eq!(
        foreign_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
        ),
        PolicyApprovalCeiling::Proposed
    );
}

#[test]
fn widen_on_request_path() {
    let capped = foreign_agent_effective_ceiling(
        PolicyApprovalCeiling::Auto,
        PolicyApprovalCeiling::Proposed,
    );

    assert_eq!(
        foreign_agent_ceiling_after_widen_request(
            capped,
            PolicyApprovalCeiling::Auto,
            &GateDecision::pending(vec![GateReasonCode::PendingActorCeiling]),
        ),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        foreign_agent_ceiling_after_widen_request(
            capped,
            PolicyApprovalCeiling::Auto,
            &GateDecision::allow(),
        ),
        PolicyApprovalCeiling::Auto
    );
}
