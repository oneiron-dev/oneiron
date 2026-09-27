//! Vault-resident behaviour rows: precedence, changeability, and deciding receipts.
use super::*;
use crate::gate::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};

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

#[test]
fn scoped_policy_rows_narrow_and_precedence_row_changes_result() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let project = test_id(0x32);
    let other_project = test_id(0x38);
    let thread = test_id(0x33);
    let other_thread = test_id(0x39);
    let subproject = test_id(0x3A);
    let rows = vec![
        row(
            "threshold-vault",
            "proposal_check_threshold",
            Value::from(100_u64),
            "vault",
            None,
        ),
        row(
            "threshold-project",
            "proposal_check_threshold",
            Value::from(2_u64),
            "project",
            Some(project),
        ),
        row(
            "vault",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "vault",
            None,
        ),
        row(
            "project",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "project",
            Some(project),
        ),
        row(
            "thread",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "thread",
            Some(thread),
        ),
        row(
            "subproject",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "sub_project",
            Some(subproject),
        ),
        row(
            "other-thread",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "thread",
            Some(other_thread),
        ),
    ];
    put_policy_manifest_bytes(&vault, test_id(0x34), &manifest(rows.clone()))?;
    let policy = resolve(&vault)?;
    assert!(!policy.is_fail_closed());
    let mut effect = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    effect
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    let decide =
        |scope: PolicyEvaluationScope| policy.evaluate_gate_in_scope(&effect, None, &scope);
    let vault_decision = decide(PolicyEvaluationScope::default());
    assert_eq!(vault_decision.policy_row_ref(), Some("vault"));
    assert_eq!(vault_decision.precedence_row_ref(), Some(None)); // missing row -> shipped-data fallback
    assert_ne!(
        vault_decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    assert_eq!(policy.proposal_check_threshold(), 100);
    let in_project = PolicyEvaluationScope {
        project: Some(project),
        ..Default::default()
    };
    assert_eq!(policy.proposal_check_threshold_in_scope(&in_project), 2);
    assert_eq!(
        policy.proposal_check_threshold_in_scope(&PolicyEvaluationScope {
            project: Some(other_project),
            ..Default::default()
        }),
        100
    );
    let hidden = decide(PolicyEvaluationScope {
        project: Some(project),
        hidden_world: true,
        ..Default::default()
    });
    assert!(hidden.policy_row_ref().is_none());
    let hidden_refusal = hidden.policy_refusal().expect("hidden refusal");
    assert!(
        hidden_refusal.level.is_none()
            && hidden_refusal.row_ref.is_none()
            && hidden_refusal.role.is_none()
    );
    let project_decision = decide(in_project);
    let refusal = project_decision
        .policy_refusal()
        .expect("typed policy refusal");
    assert_eq!(project_decision.outcome(), GateOutcome::Pending);
    assert_eq!(refusal.row_ref.as_deref(), Some("project"));
    assert_eq!(
        refusal.level.as_deref(),
        Some(format!("project:{}", project.to_hex()).as_str())
    );
    assert_eq!(refusal.role, Some("policy_power_holder"));
    assert_eq!(project_decision.policy_row_ref(), Some("project"));
    assert_eq!(
        project_decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    let thread_decision = decide(PolicyEvaluationScope {
        project: Some(project),
        thread: Some(thread),
        ..Default::default()
    });
    assert_eq!(thread_decision.policy_row_ref(), Some("project")); // thread cannot widen by default
    let outside = decide(PolicyEvaluationScope {
        project: Some(other_project),
        thread: Some(other_thread),
        ..Default::default()
    });
    assert_eq!(outside.policy_row_ref(), Some("other-thread")); // thread narrows its project
    assert_eq!(
        outside.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );

    let nested = decide(PolicyEvaluationScope {
        project: Some(other_project),
        subproject: Some(subproject),
        ..Default::default()
    });
    assert_eq!(nested.policy_row_ref(), Some("subproject"));
    assert_eq!(
        nested.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );

    // Only a vault row can set the order. Changing data changes the result;
    // even most-specific remains inside the vault's permissive envelope.
    let mut alternate = rows;
    alternate.push(row(
        "order",
        "scope_precedence",
        Value::from("most_specific"),
        "vault",
        None,
    ));
    put_policy_manifest_bytes(&vault, test_id(0x34), &manifest(alternate))?;
    let policy = resolve(&vault)?;
    let changed = policy.evaluate_gate_in_scope(
        &effect,
        None,
        &PolicyEvaluationScope {
            project: Some(project),
            thread: Some(thread),
            ..Default::default()
        },
    );
    assert_eq!(changed.policy_row_ref(), Some("thread"));
    assert_eq!(changed.precedence_row_ref(), Some(Some("order")));
    assert_ne!(
        changed.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    Ok(())
}

#[test]
fn explicit_child_override_releases_parent_but_stays_below_vault() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let project = test_id(0x70);
    let thread = test_id(0x71);
    let mut override_row = row(
        "thread",
        "comm_opt_out_posture",
        Value::from("allow_with_receipt"),
        "thread",
        Some(thread),
    );
    let Value::Map(fields) = &mut override_row else {
        unreachable!()
    };
    fields.push((Value::from("override_parent"), Value::Boolean(true)));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &manifest(vec![
            row(
                "vault",
                "comm_opt_out_posture",
                Value::from("allow_with_receipt"),
                "vault",
                None,
            ),
            row(
                "project",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "project",
                Some(project),
            ),
            override_row.clone(),
        ]),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    effect
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    let scope = PolicyEvaluationScope {
        project: Some(project),
        thread: Some(thread),
        ..Default::default()
    };
    let decision = policy.evaluate_gate_in_scope(&effect, None, &scope);
    assert_eq!(decision.policy_row_ref(), Some("thread"));
    assert_ne!(
        decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    // A restrictive vault cap survives even a holder-authorized override.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &manifest(vec![
            row(
                "vault",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "vault",
                None,
            ),
            row(
                "project",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "project",
                Some(project),
            ),
            override_row,
        ]),
    )?;
    let decision = resolve(&vault)?.evaluate_gate_in_scope(&effect, None, &scope);
    assert_eq!(decision.policy_row_ref(), Some("vault"));
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    Ok(())
}

#[test]
fn shipped_values_and_row_edits_change_behaviour_without_code_changes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x36), &default_policy_manifest())?;
    let policy = resolve(&vault)?;
    assert_eq!(policy.proposal_check_threshold(), 1_000_000);
    assert_eq!(
        policy
            .policy_value_row(
                PolicyValueKey::CommOptOutPosture,
                &PolicyEvaluationScope::default()
            )
            .unwrap()
            .row_ref,
        "default.comm_opt_out_posture"
    );
    let mut modified = default_policy_manifest();
    rewrite_policy_manifest_entries(&mut modified, |entries| {
        let (_, Value::Array(rows)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("policy_values"))
            .unwrap()
        else {
            panic!("policy rows");
        };
        let Value::Map(posture) = &mut rows[0] else {
            panic!("posture row");
        };
        posture
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("value"))
            .unwrap()
            .1 = Value::from("allow_with_receipt");
        let Value::Map(threshold) = &mut rows[1] else {
            panic!("threshold row");
        };
        threshold
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("value"))
            .unwrap()
            .1 = Value::from(3);
    });
    put_policy_manifest_bytes(&vault, test_id(0x36), &modified)?;
    let policy = resolve(&vault)?;
    assert_eq!(policy.proposal_check_threshold(), 3);
    assert_eq!(
        policy
            .policy_value_row(
                PolicyValueKey::CommOptOutPosture,
                &PolicyEvaluationScope::default()
            )
            .unwrap()
            .value,
        PolicyValue::CommOptOutPosture(CommOptOutPosture::AllowWithReceipt)
    );
    let mut effect = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    effect
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    let decision = policy.evaluate_gate(&effect);
    assert_eq!(
        decision.policy_row_ref(),
        Some("default.comm_opt_out_posture")
    );
    assert_ne!(
        decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    Ok(())
}

#[test]
fn changed_precedence_still_cannot_widen_vault_and_scoped_meta_row_is_rejected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let project = test_id(0x40);
    let thread = test_id(0x41);
    let rows = vec![
        row(
            "vault",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "vault",
            None,
        ),
        row(
            "thread",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "thread",
            Some(thread),
        ),
        row(
            "order",
            "scope_precedence",
            Value::from("most_specific"),
            "vault",
            None,
        ),
    ];
    put_policy_manifest_bytes(&vault, test_id(0x4B), &manifest(rows))?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    effect
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    let decision = policy.evaluate_gate_in_scope(
        &effect,
        None,
        &PolicyEvaluationScope {
            project: Some(project),
            thread: Some(thread),
            ..Default::default()
        },
    );
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    assert_eq!(decision.policy_row_ref(), Some("vault"));
    let (_tmp, invalid_vault) = temp_vault();
    put_policy_manifest_bytes(
        &invalid_vault,
        test_id(0x4C),
        &manifest(vec![row(
            "order",
            "scope_precedence",
            Value::from("nested_narrowing"),
            "project",
            Some(project),
        )]),
    )?;
    assert!(resolve(&invalid_vault)?.is_fail_closed());
    Ok(())
}

#[test]
fn duplicate_or_invalid_policy_value_rows_fail_closed() -> Result<()> {
    for rows in [
        vec![
            row(
                "a",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "vault",
                None,
            ),
            row(
                "b",
                "comm_opt_out_posture",
                Value::from("allow_with_receipt"),
                "vault",
                None,
            ),
        ],
        vec![row(
            "a",
            "proposal_check_threshold",
            Value::from(0),
            "vault",
            None,
        )],
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x37), &manifest(rows))?;
        assert!(resolve(&vault)?.is_fail_closed());
    }
    Ok(())
}

#[test]
fn policy_why_is_optional_and_owner_text_outweighs_drafted_text() -> Result<()> {
    use crate::gate::policy_values::WhySource;
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x4E),
        &manifest(vec![row(
            "whyless",
            "proposal_check_threshold",
            Value::from(9),
            "vault",
            None,
        )]),
    )?;
    let policy = resolve(&vault)?;
    let mut value_row = policy
        .policy_value_row(
            PolicyValueKey::ProposalCheckThreshold,
            &PolicyEvaluationScope::default(),
        )
        .unwrap()
        .clone();
    assert!(value_row.why.is_none());
    let draft_bytes = crate::gate::policy_values::with_policy_why(
        &manifest(vec![row(
            "whyless",
            "proposal_check_threshold",
            Value::from(9),
            "vault",
            None,
        )]),
        "whyless",
        "model draft",
        true,
    )
    .expect("draft fills empty row");
    assert!(
        crate::gate::policy_values::with_policy_why(&draft_bytes, "whyless", "later draft", true)
            .is_none()
    );
    let owner_bytes =
        crate::gate::policy_values::with_policy_why(&draft_bytes, "whyless", "owner reason", false)
            .expect("owner replaces draft");
    assert!(
        crate::gate::policy_values::with_policy_why(&owner_bytes, "whyless", "late draft", true)
            .is_none()
    );
    assert!(value_row.accept_draft_why("model draft"));
    assert_eq!(value_row.why.as_ref().unwrap().source, WhySource::Drafted);
    assert!(value_row.set_owner_why("owner reason"));
    assert!(!value_row.accept_draft_why("new draft"));
    assert_eq!(value_row.why.as_ref().unwrap().text, "owner reason");
    let mut authored = rmpv::decode::read_value(
        &mut manifest(vec![row(
            "owner-reason",
            "proposal_check_threshold",
            Value::from(7),
            "vault",
            None,
        )])
        .as_slice(),
    )
    .unwrap();
    let Value::Map(ref mut entries) = authored else {
        unreachable!()
    };
    let (_, Value::Array(rows)) = entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("policy_values"))
        .unwrap()
    else {
        unreachable!()
    };
    let Value::Map(fields) = &mut rows[0] else {
        unreachable!()
    };
    fields.push((
        Value::from("why"),
        Value::Map(vec![
            (Value::from("text"), Value::from("authored why")),
            (Value::from("source"), Value::from("owner")),
        ]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &authored).unwrap();
    put_policy_manifest_bytes(&vault, test_id(0x4E), &bytes)?;
    let policy = resolve(&vault)?;
    let row = policy
        .policy_value_row(
            PolicyValueKey::ProposalCheckThreshold,
            &PolicyEvaluationScope::default(),
        )
        .unwrap();
    assert_eq!(row.why.as_ref().unwrap().text, "authored why");
    Ok(())
}

#[test]
fn hidden_world_refusal_does_not_disclose_row_level_or_role() {
    let decision = GateDecision::pending(vec![GateReasonCode::PendingCounterpartyOptOut])
        .with_policy_refusal(Some("world:secret".to_owned()), Some("private-rule"), true);
    let refusal = decision.policy_refusal().unwrap();
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(refusal.level.is_none() && refusal.row_ref.is_none() && refusal.role.is_none());
}

#[test]
fn nonholder_override_is_inert_typed_proposal() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x73);
    let manifest_id = test_id(0x74);
    let project = test_id(0x75);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")?;
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut requested = row(
        "request",
        "comm_opt_out_posture",
        Value::from("allow_with_receipt"),
        "project",
        Some(project),
    );
    let Value::Map(fields) = &mut requested else {
        unreachable!()
    };
    fields.push((Value::from("override_parent"), Value::Boolean(true)));
    let proposed = vault
        .propose_policy_value_override(&owner, manifest_id, manifest(vec![requested]), 2)?
        .expect("non-holder receives proposal");
    assert_eq!(proposed.row_ref, "request");
    assert_eq!(proposed.scope, format!("project:{}", project.to_hex()));
    assert!(vault.get(&manifest_id)?.is_none());
    Ok(())
}
