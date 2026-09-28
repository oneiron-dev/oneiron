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
fn scoped_policy_rows_narrow_and_precedence_row_changes_result() -> Result<()> {
    use crate::gate::policy_values::{
        PolicyPrecedence, PolicyRowScope, PolicyValueRow, resolve_value,
    };
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x31);
    let project = test_id(0x32);
    let other_project = test_id(0x38);
    let rows = vec![
        row(
            "threshold-vault",
            "proposal_check_threshold",
            Value::from(100_u64),
            "vault",
            None,
        ),
        row(
            "threshold-world",
            "proposal_check_threshold",
            Value::from(5_u64),
            "world",
            Some(world),
        ),
        row(
            "threshold-project",
            "proposal_check_threshold",
            Value::from(20_u64),
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
    ];
    put_policy_manifest_bytes(&vault, test_id(0x34), &manifest(rows.clone()))?;
    let policy = resolve(&vault)?;
    assert!(!policy.is_fail_closed());
    let vault_decision = policy.evaluate_gate(&opted_out_effect());
    assert_eq!(vault_decision.policy_row_ref(), Some("vault"));
    assert_eq!(vault_decision.precedence_row_ref(), Some(None)); // missing row -> shipped-data fallback
    assert_ne!(
        vault_decision.reason_codes(),
        &[GateReasonCode::PendingCounterpartyOptOut]
    );
    assert_eq!(policy.proposal_check_threshold(), 100);
    let decided = |scope: &PolicyEvaluationScope| {
        let source = policy.proposal_check_threshold_source(scope);
        (source.threshold, source.deciding_row)
    };
    let in_project = PolicyEvaluationScope {
        project: Some(project),
        ..Default::default()
    };
    assert_eq!(
        decided(&in_project),
        (20, Some("threshold-project".to_owned()))
    );
    let outside = PolicyEvaluationScope {
        project: Some(other_project),
        ..Default::default()
    };
    assert_eq!(decided(&outside), (100, Some("threshold-vault".to_owned())));
    // Nested narrowing: the world row narrows every project inside it.
    let in_world = PolicyEvaluationScope {
        world: Some(world),
        project: Some(project),
        ..Default::default()
    };
    assert_eq!(decided(&in_world), (5, Some("threshold-world".to_owned())));
    assert!(
        policy
            .proposal_check_threshold_source(&in_world)
            .shipped_default_precedence
    );

    // The resolver is level-generic; which levels a key admits is checked at
    // the door (`row_at_unadmitted_level_is_refused`). A narrower thread row
    // beats both its project and the vault, and only inside that project.
    let thread = test_id(0x33);
    let generic = |row_ref: &str, value: u64, scope: PolicyRowScope| PolicyValueRow {
        row_ref: row_ref.to_owned(),
        key: PolicyValueKey::ProposalCheckThreshold,
        value: PolicyValue::ProposalCheckThreshold(value),
        scope,
        why: None,
        override_parent: false,
    };
    let chain = [
        generic("vault", 100, PolicyRowScope::Vault),
        generic("project", 20, PolicyRowScope::Project(project)),
        generic("thread", 3, PolicyRowScope::Thread(thread)),
    ];
    let pick = |scope: PolicyEvaluationScope| {
        let resolved = resolve_value(
            &chain,
            PolicyValueKey::ProposalCheckThreshold,
            &scope,
            PolicyPrecedence::NestedNarrowing,
            PolicyValue::ProposalCheckThreshold(1_000_000),
        );
        (
            resolved.value,
            resolved.deciding_row.map(|row| row.row_ref.clone()),
        )
    };
    assert_eq!(
        pick(PolicyEvaluationScope {
            project: Some(project),
            thread: Some(thread),
            ..Default::default()
        }),
        (
            PolicyValue::ProposalCheckThreshold(3),
            Some("thread".to_owned())
        )
    );
    assert_eq!(
        pick(PolicyEvaluationScope {
            project: Some(other_project),
            thread: Some(test_id(0x39)),
            ..Default::default()
        }),
        (
            PolicyValue::ProposalCheckThreshold(100),
            Some("vault".to_owned())
        )
    );

    // Only a vault row can set the order. Changing data changes the result;
    // even most-specific remains inside the vault's envelope.
    let mut alternate = rows;
    alternate.push(row(
        "order",
        "scope_precedence",
        Value::from("most_specific"),
        "vault",
        None,
    ));
    put_policy_manifest_bytes(&vault, test_id(0x34), &manifest(alternate))?;
    let changed = resolve(&vault)?.proposal_check_threshold_source(&in_world);
    assert_eq!(changed.threshold, 20);
    assert_eq!(changed.deciding_row.as_deref(), Some("threshold-project"));
    assert_eq!(changed.precedence_row.as_deref(), Some("order"));
    assert!(!changed.shipped_default_precedence);
    Ok(())
}
#[test]
fn explicit_child_override_releases_parent_but_stays_below_vault() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x6F);
    let project = test_id(0x70);
    let mut override_row = row(
        "project",
        "proposal_check_threshold",
        Value::from(60),
        "project",
        Some(project),
    );
    let Value::Map(fields) = &mut override_row else {
        unreachable!()
    };
    fields.push((Value::from("override_parent"), Value::Boolean(true)));
    let world_row = row(
        "world",
        "proposal_check_threshold",
        Value::from(10),
        "world",
        Some(world),
    );
    let scope = PolicyEvaluationScope {
        world: Some(world),
        project: Some(project),
        ..Default::default()
    };
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &manifest(vec![
            row(
                "vault",
                "proposal_check_threshold",
                Value::from(100),
                "vault",
                None,
            ),
            world_row.clone(),
            override_row.clone(),
        ]),
    )?;
    let source = resolve(&vault)?.proposal_check_threshold_source(&scope);
    assert_eq!(source.threshold, 60);
    assert_eq!(source.deciding_row.as_deref(), Some("project"));
    // A restrictive vault cap survives even an explicit override.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &manifest(vec![
            row(
                "vault",
                "proposal_check_threshold",
                Value::from(40),
                "vault",
                None,
            ),
            world_row,
            override_row,
        ]),
    )?;
    let source = resolve(&vault)?.proposal_check_threshold_source(&scope);
    assert_eq!(source.threshold, 40);
    assert_eq!(source.deciding_row.as_deref(), Some("vault"));
    Ok(())
}
#[test]
fn shipped_values_and_row_edits_change_behaviour_without_code_changes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x36), &default_policy_manifest().unwrap())?;
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
    let mut modified = default_policy_manifest().unwrap();
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
    let rows = vec![
        row(
            "vault",
            "proposal_check_threshold",
            Value::from(10),
            "vault",
            None,
        ),
        row(
            "project",
            "proposal_check_threshold",
            Value::from(50),
            "project",
            Some(project),
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
    let source = resolve(&vault)?.proposal_check_threshold_source(&PolicyEvaluationScope {
        project: Some(project),
        ..Default::default()
    });
    assert_eq!(source.threshold, 10);
    assert_eq!(source.deciding_row.as_deref(), Some("vault"));
    assert_eq!(source.precedence_row.as_deref(), Some("order"));
    let scoped_meta = manifest(vec![row(
        "order",
        "scope_precedence",
        Value::from("nested_narrowing"),
        "project",
        Some(project),
    )]);
    let refused = vault.install_owner_policy_manifest(
        &owner(&vault, 0x4A)?,
        test_id(0x4D),
        scoped_meta.clone(),
        2,
    );
    assert!(
        matches!(
            refused,
            Err(crate::Error::Gate(
                crate::error::GateError::PolicyValueLevelNotAdmitted {
                    key: "scope_precedence",
                    level: "project",
                }
            ))
        ),
        "{refused:?}"
    );
    let (_tmp, invalid_vault) = temp_vault();
    put_policy_manifest_bytes(&invalid_vault, test_id(0x4C), &scoped_meta)?;
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
                "proposal_check_threshold",
                Value::from(5),
                "project",
                Some(test_id(0x3B)),
            ),
        ],
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x37), &manifest(rows))?;
        assert!(resolve(&vault)?.is_fail_closed());
    }
    // The identical row in two manifests (a copied template) is one statement.
    let (_tmp, vault) = temp_vault();
    let copied = manifest(vec![row(
        "a",
        "comm_opt_out_posture",
        Value::from("escalate"),
        "vault",
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x37), &copied)?;
    put_policy_manifest_bytes(&vault, test_id(0x38), &copied)?;
    assert!(!resolve(&vault)?.is_fail_closed());
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
fn proposal_threshold_project_row_applies_inside_its_project_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let project = test_id(0x85);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x86),
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
        ]),
    )?;
    let mut outside = source_trust_claim(ClaimSource::UserStated);
    outside.approval = ClaimApprovalStatus::Proposed;
    let mut inside = outside.clone();
    inside.scope = Some(Value::Map(vec![(
        Value::from("scopeProjectId"),
        Value::from(project.to_hex()),
    )]));
    for (seed, body, deciding_row, threshold) in [
        (0x87, &inside, "project-threshold", 1),
        (0x88, &outside, "vault-threshold", 100),
    ] {
        let (candidate, envelope) = claim_candidate_write_parts(&vault, body)?;
        let actor = envelope.actor().entity_ref();
        let id = test_id(seed);
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        let receipt = vault
            .proposal_submission_receipt(&actor, &format!("claim:{}", id.to_hex()))?
            .expect("durable proposal receipt");
        assert_eq!(receipt.policy_source.threshold, threshold);
        assert_eq!(
            receipt.policy_source.deciding_row.as_deref(),
            Some(deciding_row)
        );
        assert!(receipt.policy_source.precedence_row.is_none());
        assert!(receipt.policy_source.shipped_default_precedence);
    }
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

#[test]
fn flat_opt_out_field_decides_nothing() -> Result<()> {
    for (flat, row_value, held) in [
        ("allow_with_receipt", "escalate", true),
        ("escalate", "allow_with_receipt", false),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x97),
            &encode_policy_manifest(vec![
                (Value::from("comm_opt_out_posture"), Value::from(flat)),
                (
                    Value::from("policy_values"),
                    Value::Array(vec![row(
                        "vault-posture",
                        "comm_opt_out_posture",
                        Value::from(row_value),
                        "vault",
                        None,
                    )]),
                ),
            ]),
        )?;
        let policy = resolve(&vault)?;
        assert!(!policy.is_fail_closed());
        let decision = policy.evaluate_gate(&opted_out_effect());
        assert_eq!(decision.policy_row_ref(), Some("vault-posture"));
        assert_eq!(
            decision.reason_codes() == [GateReasonCode::PendingCounterpartyOptOut],
            held
        );
    }
    Ok(())
}
