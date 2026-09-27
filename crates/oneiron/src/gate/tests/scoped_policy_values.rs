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
        vec![
            row(
                "duplicate",
                "comm_opt_out_posture",
                Value::from("escalate"),
                "vault",
                None,
            ),
            row(
                "duplicate",
                "comm_opt_out_posture",
                Value::from("allow_with_receipt"),
                "project",
                Some(test_id(0x3B)),
            ),
        ],
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
    put_policy_manifest_bytes(&vault, manifest_id, &manifest(Vec::new()))?;
    let before = vault.get(&manifest_id)?.expect("base manifest");
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
    assert_eq!(vault.get(&manifest_id)?, Some(before));
    Ok(())
}

#[test]
fn nonholder_cannot_delete_restrictive_row_or_change_other_manifest_fields() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x76);
    let id = test_id(0x77);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")?;
    let human = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let project = test_id(0x78);
    let old = manifest(vec![row(
        "restrict",
        "comm_opt_out_posture",
        Value::from("escalate"),
        "project",
        Some(project),
    )]);
    put_policy_manifest_bytes(&vault, id, &old)?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x7D),
        &manifest(vec![row(
            "vault-open",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "vault",
            None,
        )]),
    )?;
    let mut input = external_effect_gate_input("sender", "send", "line").gate_input(None, None);
    input
        .external_effect
        .as_mut()
        .unwrap()
        .counterparty_opted_out = true;
    let inside = PolicyEvaluationScope {
        project: Some(project),
        ..Default::default()
    };
    assert_eq!(
        resolve(&vault)?
            .evaluate_gate_in_scope(&input, None, &inside)
            .reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    for replacement in [manifest(Vec::new()), {
        let mut bytes = old.clone();
        rewrite_policy_manifest_entries(&mut bytes, |entries| {
            entries.push((Value::from("auto_checker"), Value::from("unapproved")));
        });
        bytes
    }] {
        assert!(
            vault
                .install_owner_policy_manifest(&human, id, replacement, 3)
                .is_err()
        );
        assert_eq!(vault.get(&id)?, Some(old.clone()));
        assert_eq!(
            resolve(&vault)?
                .evaluate_gate_in_scope(&input, None, &inside)
                .reason_codes(),
            &[GateReasonCode::PendingCounterpartyOptOut]
        );
    }
    Ok(())
}

#[test]
fn override_proposal_names_the_unauthorized_row_and_rejects_other_edits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x79);
    let id = test_id(0x7A);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")?;
    let human = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    put_policy_manifest_bytes(&vault, id, &manifest(Vec::new()))?;
    let override_row = |name: &str, project: EntityId| {
        let Value::Map(mut fields) = row(
            name,
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "project",
            Some(project),
        ) else {
            unreachable!()
        };
        fields.push((Value::from("override_parent"), Value::Boolean(true)));
        Value::Map(fields)
    };
    let first = test_id(0x7B);
    let second = test_id(0x7C);
    let proposed = vault
        .propose_policy_value_override(
            &human,
            id,
            manifest(vec![
                override_row("first", first),
                override_row("second", second),
            ]),
            3,
        )?
        .expect("inert first unauthorized override");
    assert_eq!(proposed.row_ref, "first");
    assert_eq!(proposed.scope, format!("project:{}", first.to_hex()));
    let other = manifest(vec![
        row(
            "not-override",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "project",
            Some(first),
        ),
        override_row("second", second),
    ]);
    assert!(
        vault
            .propose_policy_value_override(&human, id, other, 3)
            .is_err()
    );
    assert_eq!(vault.get(&id)?, Some(manifest(Vec::new())));
    Ok(())
}

#[test]
fn project_threshold_crossing_receipt_names_deciding_row_and_precedence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let project = test_id(0x81);
    let manifest_id = test_id(0x82);
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &manifest(vec![
            row(
                "vault-threshold",
                "proposal_check_threshold",
                Value::from(100),
                "vault",
                None,
            ),
            row(
                "project-threshold",
                "proposal_check_threshold",
                Value::from(1),
                "project",
                Some(project),
            ),
            row(
                "order",
                "scope_precedence",
                Value::from("nested_narrowing"),
                "vault",
                None,
            ),
        ]),
    )?;
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Proposed;
    body.scope = Some(Value::Map(vec![(
        Value::from("scopeProjectId"),
        Value::from(project.to_hex()),
    )]));
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    let actor = envelope.actor().entity_ref();
    for (seed, expected_count) in [(0x83, 1), (0x84, 2)] {
        let id = test_id(seed);
        vault
            .batch()
            .claim_candidate(&id, candidate.clone(), &envelope, test_time(3), 3)
            .commit()?;
        let receipt = vault
            .proposal_submission_receipt(&actor, &format!("claim:{}", id.to_hex()))?
            .expect("durable proposal receipt");
        assert_eq!(receipt.count, expected_count);
        assert_eq!(receipt.policy_source.threshold, 1);
        assert_eq!(
            receipt.policy_source.deciding_row.as_deref(),
            Some("project-threshold")
        );
        assert_eq!(
            receipt.policy_source.precedence_row.as_deref(),
            Some("order")
        );
        assert!(!receipt.policy_source.shipped_default_precedence);
    }
    let check = vault
        .proposal_submission_check(&actor)?
        .expect("second write crosses threshold");
    assert_eq!(check.threshold, 1);
    assert_eq!(
        check.policy_source.deciding_row.as_deref(),
        Some("project-threshold")
    );
    assert_eq!(check.policy_source.precedence_row.as_deref(), Some("order"));
    let first = vault
        .proposal_submission_receipt_at(&actor, 1)?
        .expect("immutable first receipt");
    assert_eq!(
        first.policy_source.deciding_row.as_deref(),
        Some("project-threshold")
    );
    let revised = manifest(vec![
        row(
            "vault-threshold",
            "proposal_check_threshold",
            Value::from(100),
            "vault",
            None,
        ),
        row(
            "project-threshold",
            "proposal_check_threshold",
            Value::from(80),
            "project",
            Some(project),
        ),
        row(
            "order",
            "scope_precedence",
            Value::from("nested_narrowing"),
            "vault",
            None,
        ),
    ]);
    put_policy_manifest_bytes(&vault, manifest_id, &revised)?;
    assert_eq!(
        vault.proposal_submission_receipt_at(&actor, 1)?.unwrap(),
        first
    );
    assert_eq!(vault.proposal_submission_check(&actor)?.unwrap(), check);
    Ok(())
}

#[test]
fn effect_door_uses_verified_project_and_thread_origin_and_persists_deciding_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let holder_id = test_id(0x86);
    vault.put_entity(&holder_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"holder")?;
    let holder = vault.authenticate_owner(
        holder_id,
        &holder_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.initialize_shared_vault(
        &holder,
        42,
        None,
        &[crate::federation::InitialSharedMember {
            member_ref: holder_id,
            role: Some(crate::federation::FederationGrantRole::Owner),
        }],
        1,
    )?;
    let root = vault.root_project()?;
    let root_record = vault.project(root)?.expect("root");
    let leader = EntityId::from_hex(&root_record.leader)?;
    let project_a = test_id(0x87);
    let project_b = test_id(0x88);
    for project in [project_a, project_b] {
        vault.put_project(
            project,
            &crate::workspace_roster::ProjectRecord::new(project, Some(root), root, leader),
            2,
        )?;
    }
    let project_c = test_id(0x98);
    vault.put_project(
        project_c,
        &crate::workspace_roster::ProjectRecord::new(project_c, Some(project_a), root, leader),
        2,
    )?;
    let thread_a = EntityId::from_hex(&vault.project(project_a)?.unwrap().home_room)?;
    let rows = vec![
        row(
            "vault-send",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "vault",
            None,
        ),
        row(
            "project-a",
            "comm_opt_out_posture",
            Value::from("escalate"),
            "project",
            Some(project_a),
        ),
        row(
            "thread-a",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "thread",
            Some(thread_a),
        ),
        row(
            "subproject-c",
            "comm_opt_out_posture",
            Value::from("allow_with_receipt"),
            "sub_project",
            Some(project_c),
        ),
    ];
    let mut rows = rows;
    for position in [2, 3] {
        let Value::Map(fields) = &mut rows[position] else {
            unreachable!()
        };
        fields.push((Value::from("override_parent"), Value::Boolean(true)));
    }
    let grant = external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from("normal"),
            ),
        ]),
        None,
    );
    let manifest_id = test_id(0x89);
    let data = encode_policy_manifest(vec![
        (Value::from("policy_values"), Value::Array(rows)),
        grant,
    ]);
    vault.install_owner_policy_manifest(&holder, manifest_id, data, 3)?;
    let contact_id = test_id(0x8A);
    let counterparty = "scope-send@example.com";
    vault.create_counterparty_contact(
        &contact_id,
        &CounterpartyContactRecord::user_introduction(test_id(0x8B), counterparty, 4)?,
    )?;
    vault.opt_out_counterparty_contact(&contact_id, CounterpartyOptOutReason::Stop, 5)?;
    let policy = resolve(&vault)?;
    for (label, origin, expected_outcome, expected_row) in [
        ("project-a", project_a, GateOutcome::Pending, "project-a"),
        ("project-b", project_b, GateOutcome::Allow, "vault-send"),
        ("thread-a", thread_a, GateOutcome::Allow, "thread-a"),
        (
            "subproject-c",
            project_c,
            GateOutcome::Allow,
            "subproject-c",
        ),
    ] {
        let mut effect = external_effect_gate_input("sender", "send", "line");
        effect.counterparty = Some(counterparty.to_owned());
        effect.send_ref = Some(format!("intent:{label}"));
        vault.with_write_txn(|txn| {
            vault.bind_policy_effect_origin_in_txn(txn, holder_id, &effect, origin, 6)
        })?;
        let (_, decision, _) = vault.with_write_txn(|txn| {
            check_external_effect_policy(&vault.store, txn, &effect, &policy, true)
        })?;
        assert_eq!(decision.outcome(), expected_outcome, "{label}");
        assert_eq!(decision.policy_row_ref(), Some(expected_row), "{label}");
        let records = vault.store.gate_decisions(20)?;
        assert!(
            records.iter().any(|record| record
                .receipt_reasons
                .contains(&format!("policy_row_{expected_row}"))),
            "{label}"
        );
    }
    // Omitting or forging a bound origin cannot skip the project restriction.
    let mut unbound = external_effect_gate_input("sender", "send", "line");
    unbound.counterparty = Some(counterparty.to_owned());
    unbound.send_ref = Some("intent:unbound".to_owned());
    let (_, decision, _) = vault.with_write_txn(|txn| {
        check_external_effect_policy(&vault.store, txn, &unbound, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(decision.policy_row_ref().is_none());
    let mut forged = unbound;
    forged.send_ref = Some("intent:project-a".to_owned());
    forged.channel = "other".to_owned();
    let (_, forged_decision, _) = vault.with_write_txn(|txn| {
        check_external_effect_policy(&vault.store, txn, &forged, &policy, true)
    })?;
    assert_eq!(
        forged_decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    assert!(forged_decision.policy_row_ref().is_none());
    let hidden_claim_id = test_id(0x8C);
    let mut hidden_claim = source_trust_claim(ClaimSource::UserStated);
    hidden_claim.world = Some(test_id(0x8D));
    hidden_claim.scope_project = project_b;
    put_claim_body(&vault, &hidden_claim_id, &hidden_claim)?;
    let mut hidden = external_effect_gate_input("sender", "send", "line");
    hidden.counterparty = Some(counterparty.to_owned());
    hidden.send_ref = Some("intent:hidden".to_owned());
    vault.with_write_txn(|txn| {
        vault.bind_policy_effect_origin_in_txn(txn, holder_id, &hidden, hidden_claim_id, 7)
    })?;
    let (_, decision, _) = vault.with_write_txn(|txn| {
        check_external_effect_policy(&vault.store, txn, &hidden, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    let refusal = decision.policy_refusal().expect("non-disclosing hold");
    assert!(refusal.level.is_none() && refusal.row_ref.is_none() && refusal.role.is_none());
    assert!(decision.policy_row_ref().is_none());
    assert!(
        vault
            .store
            .gate_decisions(30)?
            .iter()
            .filter(|record| record.reason_codes == vec!["gate.pending.counterparty_opt_out"])
            .any(|record| !record
                .receipt_reasons
                .iter()
                .any(|reason| reason.starts_with("policy_row_")))
    );
    Ok(())
}

#[test]
fn delegated_project_holder_changes_only_their_row_and_can_explain_it() -> Result<()> {
    use crate::federation::{FederationGrantRole, InitialSharedMember};
    let (_tmp, vault) = temp_vault();
    let owner_id = test_id(0x92);
    let admin_id = test_id(0x93);
    for id in [owner_id, admin_id] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let admin = vault.authenticate_owner(
        admin_id,
        &admin_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let created = vault.initialize_shared_vault(
        &owner,
        42,
        None,
        &[
            InitialSharedMember {
                member_ref: owner_id,
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: admin_id,
                role: Some(FederationGrantRole::Admin),
            },
        ],
        1,
    )?;
    let project_a = test_id(0x94);
    let project_b = test_id(0x95);
    let grant_id = created
        .grant_refs
        .iter()
        .map(|reference| EntityId::from_hex(reference))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|id| {
            let raw = vault.get_raw(id).unwrap().unwrap();
            crate::federation::decode_federation_grant_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .unwrap()
            .member_ref
                == admin_id
        })
        .expect("Admin grant");
    let raw = vault.get_raw(&grant_id)?.unwrap();
    let mut grant = crate::federation::decode_federation_grant_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    grant.authority_scope.verbs =
        crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            "read".to_owned(),
            "policy_write".to_owned(),
        ]));
    grant.authority_scope.audience =
        crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            crate::federation::ScopeId(project_a),
        ]));
    vault
        .batch()
        .put_replicated(
            &grant_id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            test_time(2),
            2,
            &crate::federation::encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    let id = test_id(0x96);
    let rows = vec![
        row(
            "vault-threshold",
            "proposal_check_threshold",
            Value::from(100),
            "vault",
            None,
        ),
        row(
            "project-a",
            "proposal_check_threshold",
            Value::from(2),
            "project",
            Some(project_a),
        ),
        row(
            "project-b",
            "proposal_check_threshold",
            Value::from(3),
            "project",
            Some(project_b),
        ),
    ];
    put_policy_manifest_bytes(&vault, id, &manifest(rows))?;
    assert!(vault.set_policy_value_why(&admin, id, "project-a", "Because A", false, 3)?);
    assert!(
        vault
            .set_policy_value_why(&admin, id, "project-b", "Because B", false, 4)
            .is_err()
    );
    let current = vault.get(&id)?.unwrap();
    let mut mixed_override = current.clone();
    rewrite_policy_manifest_entries(&mut mixed_override, |entries| {
        let (_, Value::Array(rows)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("policy_values"))
            .unwrap()
        else {
            unreachable!()
        };
        for position in [1, 2] {
            let Value::Map(fields) = &mut rows[position] else {
                unreachable!()
            };
            fields.push((Value::from("override_parent"), Value::Boolean(true)));
        }
    });
    let proposal = vault
        .propose_policy_value_override(&admin, id, mixed_override, 4)?
        .expect("only second override needs another holder");
    assert_eq!(proposal.row_ref, "project-b");
    assert_eq!(proposal.scope, format!("project:{}", project_b.to_hex()));
    assert_eq!(vault.get(&id)?, Some(current.clone()));
    let mut changed = current;
    rewrite_policy_manifest_entries(&mut changed, |entries| {
        let (_, Value::Array(rows)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("policy_values"))
            .unwrap()
        else {
            unreachable!()
        };
        let Value::Map(fields) = &mut rows[1] else {
            unreachable!()
        };
        fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("value"))
            .unwrap()
            .1 = Value::from(1);
    });
    vault.install_owner_policy_manifest(&admin, id, changed, 5)?;
    let approved = vault.get(&id)?.unwrap();
    let mut removed = approved.clone();
    rewrite_policy_manifest_entries(&mut removed, |entries| {
        let (_, Value::Array(rows)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("policy_values"))
            .unwrap()
        else {
            unreachable!()
        };
        rows.retain(|row| match row {
            Value::Map(fields) => fields.iter().all(|(key, value)| {
                key.as_str() != Some("row_ref") || value.as_str() != Some("project-b")
            }),
            _ => true,
        });
    });
    assert!(
        vault
            .install_owner_policy_manifest(&admin, id, removed, 6)
            .is_err()
    );
    assert_eq!(vault.get(&id)?, Some(approved));
    Ok(())
}

#[test]
fn retired_flat_opt_out_posture_cannot_bypass_row_authority() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x97),
        &encode_policy_manifest(vec![(
            Value::from("comm_opt_out_posture"),
            Value::from("allow_with_receipt"),
        )]),
    )?;
    assert!(resolve(&vault)?.is_fail_closed());
    Ok(())
}
