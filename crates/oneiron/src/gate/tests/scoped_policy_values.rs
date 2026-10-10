//! Vault-resident behaviour rows: precedence, changeability, and deciding receipts.
use super::*;
use crate::gate::policy_values::PolicyEvaluationScope;

fn row(reference: &str, key: &str, value: Value, level: &str, id: Option<EntityId>) -> Value {
    let mut scope = vec![(Value::from("level"), Value::from(level))];
    if let Some(id) = id {
        scope.push((Value::from("ref"), Value::from(id.to_hex())));
    }
    Value::Map(vec![
        (Value::from("row_ref"), Value::from(reference)),
        (Value::from("key"), Value::from(key)),
        (Value::from("value"), value),
        (Value::from("scope"), Value::Map(scope)),
    ])
}
fn manifest(rows: Vec<Value>) -> Vec<u8> {
    encode_policy_manifest(vec![(Value::from("policy_values"), Value::Array(rows))])
}
fn opted_out_effect() -> GateEvaluatorInput {
    let mut effect = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    effect
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    effect
}
fn owner(vault: &crate::Vault, seed: u8) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = test_id(seed);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")?;
    vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

#[test]
fn hidden_world_refusal_does_not_disclose_row_level_or_role() -> Result<()> {
    let decision = GateDecision::pending(vec![GateReasonCode::PendingCounterpartyOptOut])
        .with_policy_refusal(Some("world:secret".to_owned()), Some("private-rule"), true);
    let refusal = decision.policy_refusal().unwrap();
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(refusal.level.is_none() && refusal.row_ref.is_none() && refusal.role.is_none());

    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x57),
        &manifest(vec![row(
            "vault-escalate",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "vault",
            None,
        )]),
    )?;
    let policy = resolve(&vault)?;
    let visible = policy.evaluate_gate(&opted_out_effect());
    let refusal = visible.policy_refusal().expect("typed policy refusal");
    assert_eq!(refusal.level.as_deref(), Some("vault"));
    assert_eq!(refusal.row_ref.as_deref(), Some("vault-escalate"));
    assert_eq!(refusal.role, Some("policy_power_holder"));
    let hidden = policy.evaluate_gate_in_scope(
        &opted_out_effect(),
        None,
        &PolicyEvaluationScope {
            hidden_world: true,
            ..Default::default()
        },
    );
    assert_eq!(
        hidden.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    assert!(hidden.policy_row_ref().is_none() && hidden.precedence_row_ref().is_none());
    let refusal = hidden.policy_refusal().expect("blocked by policy");
    assert!(refusal.level.is_none() && refusal.row_ref.is_none() && refusal.role.is_none());
    Ok(())
}

#[test]
fn row_at_unadmitted_level_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = owner(&vault, 0x90)?;
    let project = test_id(0x91);
    let thread = test_id(0x92);
    let manifest_id = test_id(0x93);
    for (unadmitted, key, level) in [
        (
            row(
                "project-opt-out",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "project",
                Some(project),
            ),
            "comm_opt_out_posture",
            "project",
        ),
        (
            row(
                "thread-threshold",
                "proposal_check_threshold",
                Value::from(3),
                "thread",
                Some(thread),
            ),
            "proposal_check_threshold",
            "thread",
        ),
    ] {
        let bytes = manifest(vec![unadmitted]);
        let refused = vault.install_owner_policy_manifest(&owner, manifest_id, bytes.clone(), 2);
        assert!(
            matches!(
                refused,
                Err(crate::Error::Gate(
                    crate::error::GateError::PolicyValueLevelNotAdmitted { key: k, level: l }
                )) if k == key && l == level
            ),
            "{refused:?}"
        );
        assert!(vault.get(&manifest_id)?.is_none());
        // A row that reached the store another way fails the resolution closed.
        let (_tmp, stored) = temp_vault();
        put_policy_manifest_bytes(&stored, manifest_id, &bytes)?;
        assert!(resolve(&stored)?.is_fail_closed());
    }
    vault.install_owner_policy_manifest(
        &owner,
        manifest_id,
        manifest(vec![row(
            "project-threshold",
            "proposal_check_threshold",
            Value::from(3),
            "project",
            Some(project),
        )]),
        3,
    )?;
    assert!(!resolve(&vault)?.is_fail_closed());
    Ok(())
}
