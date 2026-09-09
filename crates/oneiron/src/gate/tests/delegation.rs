//! Delegated grants: fold, revoke dominance, depth cap, and cross-manifest chains.

use super::*;

#[test]
fn delegated_manifest_decode_rejects_unknown_keys() -> Result<()> {
    let row = Value::Map(vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from("g")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
        (Value::from("future_row_key"), Value::Boolean(true)),
    ]);
    assert!(parse_delegated_grants(&Value::Array(vec![row])).is_none());
    let revoke = Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from("g")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
    ]);
    assert!(parse_delegated_grants(&Value::Array(vec![revoke])).is_none());

    let (_tmp, vault) = temp_vault();
    let mut cursor = Cursor::new(encode_policy_manifest(vec![]));
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
        unreachable!("manifest is a map");
    };
    entries.push((Value::from("future_pack_key"), Value::Boolean(true)));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode");
    put_policy_manifest_bytes(&vault, test_id(0xF1), &encoded)?;
    let policy = resolve(&vault)?;
    assert!(policy.diagnostics.malformed_manifest_seen);
    assert!(policy.is_fail_closed());
    assert!(policy.delegation_fold.records.is_empty());
    Ok(())
}

#[test]
fn revoke_parent_zeroes_subtree_at_fold() {
    let rows = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "root".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: None,
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::Grant {
            grant_ref: "child".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("root".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::RevokeGrant {
            grant_ref: "root".into(),
        },
    ];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(cache.effective_ceiling("root"), None);
    assert_eq!(cache.effective_ceiling("child"), None);
}

#[test]
fn revoke_dominates_grant() {
    let rows = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "g".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: None,
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::RevokeGrant {
            grant_ref: "g".into(),
        },
    ];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(cache.effective_ceiling("g"), None);
}

#[test]
fn depth_cap_8() {
    let mut rows = Vec::new();
    for i in 0..8 {
        rows.push(DelegationGrantRecord::Grant {
            grant_ref: format!("g{i}"),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: (i > 0).then(|| format!("g{}", i - 1)),
            ceiling: PolicyApprovalCeiling::Auto,
        });
    }
    assert!(fold_delegated_grants(&rows).is_some());
    rows.push(DelegationGrantRecord::Grant {
        grant_ref: "g8".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: Some("g7".into()),
        ceiling: PolicyApprovalCeiling::Auto,
    });
    assert!(fold_delegated_grants(&rows).is_none());
    let cycle = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "a".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("b".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::Grant {
            grant_ref: "b".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("a".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
    ];
    assert!(fold_delegated_grants(&cycle).is_none());
    let missing = vec![DelegationGrantRecord::Grant {
        grant_ref: "a".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: Some("missing".into()),
        ceiling: PolicyApprovalCeiling::Auto,
    }];
    assert!(fold_delegated_grants(&missing).is_none());
}

#[test]
fn adversarial_long_chain_fail_closed_no_stack_overflow() {
    const CHAIN_LEN: usize = 65_536;
    let rows = (0..CHAIN_LEN)
        .map(|i| DelegationGrantRecord::Grant {
            grant_ref: format!("{i:05}"),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: (i + 1 < CHAIN_LEN).then(|| format!("{:05}", i + 1)),
            ceiling: PolicyApprovalCeiling::Auto,
        })
        .collect::<Vec<_>>();
    assert!(fold_delegated_grants(&rows).is_none());
}

#[test]
fn fold_cache_hit() {
    let rows = vec![DelegationGrantRecord::Grant {
        grant_ref: "g".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: None,
        ceiling: PolicyApprovalCeiling::Auto,
    }];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(
        cache.effective_ceiling("g"),
        Some(PolicyApprovalCeiling::Auto),
    );
    let rebuilt = fold_delegated_grants(&rows).expect("valid rebuild");
    assert_eq!(
        rebuilt.effective_ceiling("g"),
        Some(PolicyApprovalCeiling::Auto),
    );
}

#[test]
fn delegated_ceiling_never_raises_proposed_to_auto() {
    let rows = vec![DelegationGrantRecord::Grant {
        grant_ref: "g".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: None,
        ceiling: PolicyApprovalCeiling::Proposed,
    }];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(
        cache.effective_ceiling("g"),
        Some(PolicyApprovalCeiling::Proposed)
    );
    assert_eq!(
        PolicyApprovalCeiling::Proposed.restrict(cache.effective_ceiling("g").unwrap()),
        PolicyApprovalCeiling::Proposed
    );
}

#[test]
fn delegated_grants_manifest_hash_deterministic() -> Result<()> {
    let grant = Value::Map(vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from("manifest-grant")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
    ]);
    let revoke = Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from("manifest-grant")),
    ]);
    let delegated = |row: Value| {
        vec![(
            Value::from(POLICY_DELEGATED_GRANTS_KEY),
            Value::Array(vec![row]),
        )]
    };

    let (_tmp_a, vault_a) = temp_vault();
    let grant_data = encode_policy_manifest(delegated(grant.clone()));
    put_policy_manifest_bytes(&vault_a, test_id(0xD8), &grant_data)?;
    let grant_policy_a = resolve(&vault_a)?;
    let grant_hash_a = grant_policy_a.read_frontier_hash()?;

    let (_tmp_b, vault_b) = temp_vault();
    let grant_data_b = encode_policy_manifest(delegated(grant));
    put_policy_manifest_bytes(&vault_b, test_id(0xD9), &grant_data_b)?;
    let grant_policy_b = resolve(&vault_b)?;
    assert_eq!(grant_hash_a, grant_policy_b.read_frontier_hash()?);

    let (_tmp_c, vault_c) = temp_vault();
    let revoke_data = encode_policy_manifest(delegated(revoke));
    put_policy_manifest_bytes(&vault_c, test_id(0xDA), &revoke_data)?;
    let revoke_policy = resolve(&vault_c)?;
    assert_ne!(grant_hash_a, revoke_policy.read_frontier_hash()?);

    let (_tmp_d, vault_d) = temp_vault();
    let mut duplicate_data = encode_policy_manifest(vec![(
        Value::from(POLICY_DELEGATED_GRANTS_KEY),
        Value::Array(vec![]),
    )]);
    duplicate_data = {
        let mut cursor = Cursor::new(duplicate_data.as_slice());
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
            unreachable!("manifest is a map");
        };
        entries.push((
            Value::from(POLICY_DELEGATED_GRANTS_KEY),
            Value::Array(vec![]),
        ));
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("re-encode");
        encoded
    };
    put_policy_manifest_bytes(&vault_d, test_id(0xDB), &duplicate_data)?;
    let duplicate_policy = resolve(&vault_d)?;
    assert!(duplicate_policy.diagnostics.malformed_manifest_seen);
    Ok(())
}

fn delegated_manifest_row(
    grant_ref: &str,
    actor_class: &str,
    actor_ref: Option<&str>,
    parent_grant_ref: Option<&str>,
    ceiling: &str,
) -> Value {
    let mut row = vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from(grant_ref)),
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ];
    if let Some(actor_ref) = actor_ref {
        row.push((Value::from(ACTOR_REF_KEY), Value::from(actor_ref)));
    }
    if let Some(parent) = parent_grant_ref {
        row.push((Value::from("parent_grant_ref"), Value::from(parent)));
    }
    Value::Map(row)
}

fn delegated_manifest_revoke_row(grant_ref: &str) -> Value {
    Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from(grant_ref)),
    ])
}

fn delegated_manifest_entry(rows: Vec<Value>) -> (Value, Value) {
    (Value::from(POLICY_DELEGATED_GRANTS_KEY), Value::Array(rows))
}

#[test]
fn cross_manifest_chain_order_independent() -> Result<()> {
    let run = |child_id: u8,
               root_id: u8|
     -> Result<(Option<PolicyApprovalCeiling>, Option<PolicyApprovalCeiling>)> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(child_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("child", "agent", None, Some("parent"), "proposed"),
            ])]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            test_id(root_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("parent", "agent", None, None, "auto"),
            ])]),
        )?;
        let policy = resolve(&vault)?;
        assert!(!policy.diagnostics.malformed_manifest_seen);
        Ok((
            policy.delegation_fold.effective_ceiling("parent"),
            policy.delegation_fold.effective_ceiling("child"),
        ))
    };
    let expected = (
        Some(PolicyApprovalCeiling::Auto),
        Some(PolicyApprovalCeiling::Proposed),
    );
    assert_eq!(run(0x10, 0xF0)?, expected);
    assert_eq!(run(0xF0, 0x10)?, expected);
    Ok(())
}

#[test]
fn cross_manifest_revoke_dominance() -> Result<()> {
    let run = |grant_id: u8,
               revoke_id: u8|
     -> Result<(Option<PolicyApprovalCeiling>, Option<PolicyApprovalCeiling>)> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(grant_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("parent", "agent", None, None, "auto"),
                delegated_manifest_row("child", "agent", None, Some("parent"), "auto"),
            ])]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            test_id(revoke_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_revoke_row("parent"),
            ])]),
        )?;
        let policy = resolve(&vault)?;
        assert!(!policy.diagnostics.malformed_manifest_seen);
        Ok((
            policy.delegation_fold.effective_ceiling("parent"),
            policy.delegation_fold.effective_ceiling("child"),
        ))
    };
    assert_eq!(run(0x20, 0xE0)?, (None, None));
    assert_eq!(run(0xE0, 0x20)?, (None, None));
    Ok(())
}

#[test]
fn evaluate_gate_delegation_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![delegated_manifest_entry(vec![
        delegated_manifest_row("bound-auto", "agent", Some("dispatch"), None, "auto"),
        delegated_manifest_row(
            "bound-proposed",
            "agent",
            Some("dispatch"),
            None,
            "proposed",
        ),
        delegated_manifest_row("other-class", "human", Some("dispatch"), None, "auto"),
    ])]);
    replace_actor_ceilings(&mut data, vec![actor_ceiling_row("agent", "auto")]);
    put_policy_manifest_bytes(&vault, test_id(0x30), &data)?;
    let policy = resolve(&vault)?;

    let mut exact = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    exact.actor.delegation_grant_ref = Some("bound-auto".into());
    assert_eq!(policy.evaluate_gate(&exact).outcome(), GateOutcome::Allow);

    for (grant_ref, actor_class, actor_ref) in [
        ("other-class", "agent", "dispatch"),
        ("bound-auto", "agent", "wrong"),
        ("unknown", "agent", "dispatch"),
    ] {
        let mut input = gate_evaluator_input(
            actor_class,
            Some(actor_ref),
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        input.actor.delegation_grant_ref = Some(grant_ref.into());
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert!(
            decision
                .reason_codes()
                .contains(&GateReasonCode::PendingActorCeiling)
        );
    }

    let mut revoked = exact;
    revoked.actor.delegation_grant_ref = Some("bound-auto".into());
    // A later revoke dominates the grant, regardless of manifest ordering.
    let (_tmp, revoked_vault) = temp_vault();
    put_policy_manifest_bytes(&revoked_vault, test_id(0x31), &data)?;
    put_policy_manifest_bytes(
        &revoked_vault,
        test_id(0x32),
        &encode_policy_manifest(vec![delegated_manifest_entry(vec![
            delegated_manifest_revoke_row("bound-auto"),
        ])]),
    )?;
    let revoked_policy = resolve(&revoked_vault)?;
    let decision = revoked_policy.evaluate_gate(&revoked);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(
        decision
            .reason_codes()
            .contains(&GateReasonCode::PendingActorCeiling)
    );

    let mut proposed = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    proposed.actor.delegation_grant_ref = Some("bound-auto".into());
    proposed.criticality = PolicyCriticality::Normal;
    proposed.source = Some(ClaimSource::UserStated);
    // Proposed ordinary approval must not become Auto through delegation.
    // (The gate input's approval mode is represented by criticality in this fixture.)
    proposed.actor.delegation_grant_ref = Some("bound-proposed".into());
    assert_ne!(
        policy.evaluate_gate(&proposed).outcome(),
        GateOutcome::Allow
    );

    // The ordinary actor ceiling also participates in the meet: a Proposed
    // ordinary ceiling must not be widened by a bound Auto delegation grant.
    let (_tmp, ordinary_proposed_vault) = temp_vault();
    let mut ordinary_data = encode_policy_manifest(vec![delegated_manifest_entry(vec![
        delegated_manifest_row(
            "ordinary-proposed-bound-auto",
            "agent",
            Some("dispatch"),
            None,
            "auto",
        ),
    ])]);
    replace_actor_ceilings(
        &mut ordinary_data,
        vec![actor_ceiling_row("agent", "proposed")],
    );
    put_policy_manifest_bytes(&ordinary_proposed_vault, test_id(0x33), &ordinary_data)?;
    let ordinary_policy = resolve(&ordinary_proposed_vault)?;
    let mut ordinary_input = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    ordinary_input.actor.delegation_grant_ref = Some("ordinary-proposed-bound-auto".into());
    let ordinary_decision = ordinary_policy.evaluate_gate(&ordinary_input);
    assert_eq!(ordinary_decision.outcome(), GateOutcome::Pending);
    assert!(
        ordinary_decision
            .reason_codes()
            .contains(&GateReasonCode::PendingActorCeiling)
    );
    Ok(())
}
