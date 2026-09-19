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

#[test]
fn single_valued_manifest_requires_unanimity_and_changes_frontier() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let key = Value::from("single_valued_predicates");
    let manifest = encode_policy_manifest(vec![(
        key.clone(),
        Value::Array(vec![Value::from("profile.name")]),
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x61), &manifest)?;
    let first = resolve(&vault)?;
    assert!(first.is_single_valued_predicate("profile.name"));
    let hash = first.read_frontier_hash()?;
    put_policy_manifest_bytes(&vault, test_id(0x62), &encode_policy_manifest(Vec::new()))?;
    let second = resolve(&vault)?;
    assert!(!second.is_single_valued_predicate("profile.name"));
    assert_ne!(hash, second.read_frontier_hash()?);
    let malformed = encode_policy_manifest(vec![(
        key,
        Value::Array(vec![
            Value::from("profile.name"),
            Value::from("profile.name"),
        ]),
    )]);
    assert!(decode_policy_manifest(&malformed).is_none());
    Ok(())
}

#[test]
fn foreign_door_clamps_live_claim_gate_and_widen_requires_allow() -> Result<()> {
    use crate::write_envelope::{ClaimCandidate, WriteActor, WriteProvenance};
    let (_tmp, vault) = temp_vault();
    let human = test_id(0x63);
    let introducer = test_id(0x64);
    let foreign = test_id(0x65);
    for id in [human, introducer, foreign] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"actor",
        )?;
    }
    let owner = vault.authenticate_owner(human, "principal:owner", true, GateDecisionId::now())?;
    let mut manifest = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Observed, 0)]);
    replace_actor_ceilings(
        &mut manifest,
        vec![
            actor_ceiling_row("agent", "auto"),
            actor_ceiling_row("human", "proposed"),
            actor_ceiling_row_for_ref("agent", &introducer.to_hex(), "proposed"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0x66), &manifest)?;
    vault.register_foreign_agent(
        &owner,
        foreign,
        WriteActor::new(introducer, crate::edge::EdgeActorClass::Agent),
        AgentCeiling::Auto,
    )?;
    let claim = test_id(0x67);
    let candidate = ClaimCandidate::new(
        "profile.name",
        crate::claim::ClaimSubject::Entity(human),
        Value::from("name"),
        0.8,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(foreign, crate::edge::EdgeActorClass::Agent),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("foreign-test"))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(1), 1)
        .commit()?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("held").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(vault.store.pending_gate_consents(100)?.iter().any(|row| {
        row.claim_id == *claim.as_bytes()
            && row
                .reason_codes
                .iter()
                .any(|reason| reason == "gate.pending.actor_ceiling")
    }));
    assert!(!vault.request_foreign_agent_widen(&owner, foreign, AgentCeiling::Auto)?);
    replace_actor_ceilings(
        &mut manifest,
        vec![
            actor_ceiling_row("agent", "auto"),
            actor_ceiling_row("human", "auto"),
            actor_ceiling_row_for_ref("agent", &introducer.to_hex(), "proposed"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0x66), &manifest)?;
    assert!(vault.request_foreign_agent_widen(&owner, foreign, AgentCeiling::Auto)?);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        agent_definition_ceiling_for_actor(
            &vault.store,
            &txn,
            WriteActor::new(foreign, crate::edge::EdgeActorClass::Agent)
        ),
        Some(PolicyApprovalCeiling::Auto)
    );
    Ok(())
}
