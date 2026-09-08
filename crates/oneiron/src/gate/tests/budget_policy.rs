//! ONE-1348 budget_policy manifest parse, resolution, and factory tests.

// ---------------------------------------------------------------------------
// ONE-1348 `budget_policy` manifest parse / resolution / factory tests.
//
// All fixtures and helpers stay inside this module; the existing
// `on_budget_exhausted`, gate-decision, facet/mask/disclosure, and ONE-1388
// tests above are untouched.
// ---------------------------------------------------------------------------

use super::*;

fn row_value(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn purpose_row_value(purpose: &str, floor: Option<u64>, cap: Option<u64>) -> Value {
    let mut entries = vec![("purpose", Value::from(purpose))];
    if let Some(floor) = floor {
        entries.push(("floor", Value::from(floor)));
    }
    if let Some(cap) = cap {
        entries.push(("cap", Value::from(cap)));
    }
    row_value(entries)
}

fn actor_row_value(actor_ref: &str, floor: Option<u64>, cap: Option<u64>) -> Value {
    let mut entries = vec![("actor", Value::from(actor_ref))];
    if let Some(floor) = floor {
        entries.push(("floor", Value::from(floor)));
    }
    if let Some(cap) = cap {
        entries.push(("cap", Value::from(cap)));
    }
    row_value(entries)
}

fn budget_policy_entry(rows: Vec<Value>) -> (Value, Value) {
    (Value::from(POLICY_BUDGET_POLICY_KEY), Value::Array(rows))
}

fn canonical_actor_ref(seed: u8) -> String {
    crate::test_util::entity(seed).to_hex()
}

fn resolved_table(
    vault: &crate::Vault,
    seed: u8,
    rows: Vec<Value>,
) -> Result<PolicyManifestResolution> {
    put_policy_manifest_bytes(
        vault,
        test_id(seed),
        &encode_policy_manifest(vec![budget_policy_entry(rows)]),
    )?;
    resolve(vault)
}

#[test]
fn budget_policy_absent_and_empty_resolve_identically() -> Result<()> {
    let (_tmp_absent, absent_vault) = temp_vault();
    put_policy_manifest_bytes(
        &absent_vault,
        test_id(0x30),
        &encode_policy_manifest(vec![]),
    )?;
    let (_tmp_empty, empty_vault) = temp_vault();
    put_policy_manifest_bytes(
        &empty_vault,
        test_id(0x30),
        &encode_policy_manifest(vec![budget_policy_entry(vec![])]),
    )?;

    let absent = resolve(&absent_vault)?;
    let empty = resolve(&empty_vault)?;
    assert!(
        absent
            .budget_policy()
            .expect("absent table resolves")
            .is_empty()
    );
    assert!(
        empty
            .budget_policy()
            .expect("explicit empty table resolves")
            .is_empty()
    );
    assert_eq!(absent.read_frontier_hash()?, empty.read_frontier_hash()?);
    Ok(())
}

#[test]
fn budget_policy_parses_canonical_purpose_and_actor_rows_in_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_ref = canonical_actor_ref(0x44);
    let policy = resolved_table(
        &vault,
        0x30,
        vec![
            purpose_row_value("consolidation", Some(200_000), None),
            actor_row_value(&actor_ref, Some(50_000), Some(150_000)),
        ],
    )?;
    let table = policy.budget_policy().expect("valid table");
    let rows = table.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].selector(),
        &BudgetPolicySelector::Purpose(CallPurpose::Consolidation)
    );
    assert_eq!(rows[0].floor_units(), Some(200_000));
    assert_eq!(rows[0].cap_units(), None);
    let actor_id = EntityId::from_hex(&actor_ref).expect("actor ref round-trips");
    assert_eq!(actor_id.to_hex(), actor_ref);
    assert_eq!(rows[1].selector(), &BudgetPolicySelector::Actor(actor_id));
    assert_eq!(rows[1].floor_units(), Some(50_000));
    assert_eq!(rows[1].cap_units(), Some(150_000));
    Ok(())
}

#[test]
fn budget_policy_other_purpose_matches_by_name() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolved_table(
        &vault,
        0x30,
        vec![purpose_row_value("dream_journal", Some(5), None)],
    )?;
    let table = policy.budget_policy().expect("valid table");
    match table.rows()[0].selector() {
        BudgetPolicySelector::Purpose(CallPurpose::Other { name }) => {
            assert_eq!(name, "dream_journal");
        }
        other => panic!("expected an exact-name Other purpose, got {other:?}"),
    }
    assert_ne!(
        table.rows()[0].selector(),
        &BudgetPolicySelector::Purpose(CallPurpose::Voice),
        "an Other name is never a built-in or wildcard"
    );
    Ok(())
}

#[test]
fn budget_policy_requires_selector_xor_and_floor_or_cap() {
    let actor_ref = canonical_actor_ref(0x44);
    for (label, row) in [
        (
            "neither selector",
            row_value(vec![("floor", Value::from(10_u64))]),
        ),
        (
            "both selectors",
            row_value(vec![
                ("purpose", Value::from("voice")),
                ("actor", Value::from(actor_ref.as_str())),
                ("floor", Value::from(10_u64)),
            ]),
        ),
        (
            "neither floor nor cap",
            row_value(vec![("purpose", Value::from("voice"))]),
        ),
    ] {
        let manifest = encode_policy_manifest(vec![budget_policy_entry(vec![row])]);
        assert!(
            decode_policy_manifest(&manifest).is_none(),
            "{label} row must reject the manifest"
        );
    }

    // floor: 0 and cap: 0 are both syntactically valid.
    let floor_zero =
        decode_policy_manifest(&encode_policy_manifest(vec![budget_policy_entry(vec![
            purpose_row_value("voice", Some(0), None),
        ])]))
        .expect("floor: 0 stays valid");
    assert_eq!(floor_zero.budget_policy.rows()[0].floor_units(), Some(0));
    let cap_zero =
        decode_policy_manifest(&encode_policy_manifest(vec![budget_policy_entry(vec![
            purpose_row_value("voice", None, Some(0)),
        ])]))
        .expect("cap: 0 stays valid");
    assert_eq!(cap_zero.budget_policy.rows()[0].cap_units(), Some(0));
}

#[test]
fn budget_policy_malformed_row_fails_manifest_closed() -> Result<()> {
    // A letters-bearing ref so `to_uppercase` genuinely de-canonicalizes it.
    let noncanonical_actor_ref = canonical_actor_ref(0xAB).to_uppercase();
    assert_ne!(
        noncanonical_actor_ref,
        noncanonical_actor_ref.to_lowercase()
    );
    let cases: Vec<(&str, Value)> = vec![
        ("non-array table", Value::from(42_u64)),
        ("non-map row", Value::Array(vec![Value::from("not-a-row")])),
        (
            "duplicate row key",
            Value::Array(vec![row_value(vec![
                ("purpose", Value::from("voice")),
                ("floor", Value::from(10_u64)),
                ("floor", Value::from(11_u64)),
            ])]),
        ),
        (
            "wrong integer type",
            Value::Array(vec![row_value(vec![
                ("purpose", Value::from("voice")),
                ("floor", Value::from("ten")),
            ])]),
        ),
        (
            "empty purpose",
            Value::Array(vec![purpose_row_value("", Some(10), None)]),
        ),
        (
            "non-canonical actor ref",
            Value::Array(vec![actor_row_value(
                noncanonical_actor_ref.as_str(),
                Some(10),
                None,
            )]),
        ),
        (
            "unknown row key",
            Value::Array(vec![row_value(vec![
                ("purpose", Value::from("voice")),
                ("floor", Value::from(10_u64)),
                ("bogus", Value::from(1_u64)),
            ])]),
        ),
    ];
    for (index, (label, table_value)) in cases.into_iter().enumerate() {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x30),
            &encode_policy_manifest(vec![(Value::from(POLICY_BUDGET_POLICY_KEY), table_value)]),
        )?;
        let policy = resolve(&vault)?;
        assert!(
            policy.diagnostics().malformed_manifest_seen,
            "{label} must mark the manifest malformed (case {index})"
        );
        assert!(
            policy.diagnostics().loaded_manifest_forces_fail_closed(),
            "{label} must fail the loaded manifest closed (case {index})"
        );
        assert!(
            policy.budget_policy().is_none(),
            "{label} exposes no usable table (case {index})"
        );
    }
    Ok(())
}

#[test]
fn budget_policy_multiple_manifests_preserve_resolved_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_ref = canonical_actor_ref(0x44);
    // Type-index order is ascending entity id bytes: 0x30... < 0x31....
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &encode_policy_manifest(vec![budget_policy_entry(vec![
            purpose_row_value("extraction", Some(1), None),
            actor_row_value(&actor_ref, Some(2), Some(4)),
        ])]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
            "voice",
            None,
            Some(3),
        )])]),
    )?;

    let policy = resolve(&vault)?;
    let table = policy.budget_policy().expect("valid table");
    let rows = table.rows();
    assert_eq!(rows.len(), 3);
    // Rows concatenate in resolved order: manifest scan order, then row
    // order inside each manifest; indices 0..=2 stay stable.
    assert_eq!(
        rows[0].selector(),
        &BudgetPolicySelector::Purpose(CallPurpose::Extraction)
    );
    assert_eq!(
        (rows[0].floor_units(), rows[0].cap_units()),
        (Some(1), None)
    );
    assert_eq!(
        rows[1].selector(),
        &BudgetPolicySelector::Actor(EntityId::from_hex(&actor_ref).expect("actor ref"))
    );
    assert_eq!(
        (rows[1].floor_units(), rows[1].cap_units()),
        (Some(2), Some(4))
    );
    assert_eq!(
        rows[2].selector(),
        &BudgetPolicySelector::Purpose(CallPurpose::Voice)
    );
    assert_eq!(
        (rows[2].floor_units(), rows[2].cap_units()),
        (None, Some(3))
    );
    Ok(())
}

#[test]
fn budget_policy_changes_policy_frontier_hash() -> Result<()> {
    fn frontier_hash_without_entry() -> Result<[u8; 32]> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x30), &encode_policy_manifest(vec![]))?;
        resolve(&vault)?.read_frontier_hash()
    }
    fn frontier_hash_with(rows: Vec<Value>) -> Result<[u8; 32]> {
        let (_tmp, vault) = temp_vault();
        let policy = resolved_table(&vault, 0x30, rows)?;
        policy.read_frontier_hash()
    }

    let absent = frontier_hash_without_entry()?;
    let explicit_empty = frontier_hash_with(vec![])?;
    assert_eq!(
        absent, explicit_empty,
        "absent and explicit empty hash identically"
    );

    let base = vec![purpose_row_value("consolidation", Some(100), None)];
    let base_hash = frontier_hash_with(base)?;
    assert_ne!(base_hash, absent, "present rows change the hash");

    let selector_changed =
        frontier_hash_with(vec![purpose_row_value("extraction", Some(100), None)])?;
    assert_ne!(
        selector_changed, base_hash,
        "selector change changes the hash"
    );
    let floor_changed =
        frontier_hash_with(vec![purpose_row_value("consolidation", Some(101), None)])?;
    assert_ne!(floor_changed, base_hash, "floor change changes the hash");
    let cap_changed = frontier_hash_with(vec![purpose_row_value(
        "consolidation",
        Some(100),
        Some(500),
    )])?;
    assert_ne!(cap_changed, base_hash, "cap change changes the hash");

    let ordered_ab = frontier_hash_with(vec![
        purpose_row_value("consolidation", Some(100), None),
        purpose_row_value("voice", None, Some(5)),
    ])?;
    let ordered_ba = frontier_hash_with(vec![
        purpose_row_value("voice", None, Some(5)),
        purpose_row_value("consolidation", Some(100), None),
    ])?;
    assert_ne!(ordered_ab, ordered_ba, "row order is frontier-relevant");

    // A malformed table drops its whole manifest from decoded rows; the
    // fail-closed resolution hashes deterministically and differs from
    // the well-formed hash.
    let (_tmp, malformed_vault) = temp_vault();
    put_policy_manifest_bytes(
        &malformed_vault,
        test_id(0x30),
        &encode_policy_manifest(vec![budget_policy_entry(vec![Value::from("not-a-row")])]),
    )?;
    let malformed = resolve(&malformed_vault)?;
    assert!(malformed.diagnostics().malformed_manifest_seen);
    assert!(malformed.budget_policy().is_none());
    let malformed_hash = malformed.read_frontier_hash()?;
    let malformed_again = resolve(&malformed_vault)?.read_frontier_hash()?;
    assert_eq!(
        malformed_hash, malformed_again,
        "fail-closed resolution hashes deterministically"
    );
    assert_ne!(
        malformed_hash, base_hash,
        "malformed table never aliases a well-formed hash"
    );
    Ok(())
}

#[test]
fn budget_policy_row_overflow_fails_resolution_closed() -> Result<()> {
    let overflow_row = || purpose_row_value("extraction", Some(1), None);

    // Exactly u16::MAX + 1 rows stay valid: every index 0..=65535 is
    // addressable.
    let (_tmp_ok, ok_vault) = temp_vault();
    let max_rows: Vec<Value> = (0..=usize::from(u16::MAX))
        .map(|_| overflow_row())
        .collect();
    assert_eq!(max_rows.len(), usize::from(u16::MAX) + 1);
    let ok_policy = resolved_table(&ok_vault, 0x30, max_rows)?;
    let ok_table = ok_policy.budget_policy().expect("65,536 rows stay valid");
    assert_eq!(ok_table.rows().len(), usize::from(u16::MAX) + 1);
    assert_eq!(
        ok_table.rows()[usize::from(u16::MAX)].selector(),
        &BudgetPolicySelector::Purpose(CallPurpose::Extraction),
        "index 65,535 remains addressable"
    );

    // One row more marks the resolution malformed and fails closed.
    let (_tmp_over, over_vault) = temp_vault();
    let overflow_rows: Vec<Value> = (0..=usize::from(u16::MAX))
        .map(|_| overflow_row())
        .chain(std::iter::once_with(overflow_row))
        .collect();
    assert_eq!(overflow_rows.len(), usize::from(u16::MAX) + 2);
    let over_policy = resolved_table(&over_vault, 0x30, overflow_rows)?;
    assert!(over_policy.diagnostics().malformed_manifest_seen);
    assert!(
        over_policy
            .diagnostics()
            .loaded_manifest_forces_fail_closed()
    );
    assert!(over_policy.budget_policy().is_none());
    Ok(())
}

#[test]
fn budget_policy_guard_factory_fails_closed_on_malformed_manifest() -> Result<()> {
    let actor = WriteActor::new(test_id(0x44), EdgeActorClass::Agent);

    // A malformed budget_policy table fails the loaded manifest closed
    // and the factory refuses: production never gets a legacy
    // empty-table guard.
    let (_tmp_bad, bad_vault) = temp_vault();
    put_policy_manifest_bytes(
        &bad_vault,
        test_id(0x30),
        &encode_policy_manifest(vec![budget_policy_entry(vec![Value::from("not-a-row")])]),
    )?;
    let bad = bad_vault
        .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
        .expect_err("malformed manifest refuses guard construction");
    assert!(matches!(bad, Error::InvalidConfig(_)));
    assert_eq!(bad.kind(), ErrorKind::InvalidConfig);

    // The missing-schema_version case fail-closes the same way.
    let (_tmp_schema, schema_vault) = temp_vault();
    let mut schema_data =
        encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
            "consolidation",
            Some(30),
            None,
        )])]);
    rewrite_policy_manifest_entries(&mut schema_data, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
    });
    put_policy_manifest_bytes(&schema_vault, test_id(0x30), &schema_data)?;
    let schema_policy = resolve(&schema_vault)?;
    assert!(schema_policy.diagnostics().unsupported_schema_seen);
    let schema_err = schema_vault
        .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
        .expect_err("unsupported schema refuses guard construction");
    assert!(matches!(schema_err, Error::InvalidConfig(_)));

    // Control: a valid manifest builds the policy-aware guard, and an
    // absent manifest keeps the bootstrap single-pool guard.
    let (_tmp_ok, ok_vault) = temp_vault();
    put_policy_manifest_bytes(
        &ok_vault,
        test_id(0x30),
        &encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
            "consolidation",
            Some(30),
            None,
        )])]),
    )?;
    ok_vault
        .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
        .expect("valid manifest constructs the policy-aware guard");
    let (_tmp_none, none_vault) = temp_vault();
    none_vault
        .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
        .expect("absent manifest keeps the bootstrap guard");
    Ok(())
}
