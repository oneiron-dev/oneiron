//! Project-conversion manifest policy: default, strict parse, narrowing and frontier.

use super::*;

fn conversion_row(
    leader_fallback: &str,
    roster_selection: &str,
    max_tasks: u64,
    allow_holder_override: bool,
) -> Value {
    Value::Map(vec![
        (
            Value::from("precedence"),
            Value::from("nested_narrowing_holder_override_capped_vault"),
        ),
        (Value::from("leader_fallback"), Value::from(leader_fallback)),
        (
            Value::from("roster_selection"),
            Value::from(roster_selection),
        ),
        (
            Value::from("task_holder_fallback"),
            Value::from("assignee_then_owner"),
        ),
        (Value::from("max_tasks"), Value::from(max_tasks)),
        (
            Value::from("allow_holder_override"),
            Value::Boolean(allow_holder_override),
        ),
    ])
}

fn row_entry(value: Value) -> (Value, Value) {
    (Value::from(POLICY_PROJECT_CONVERSION_KEY), value)
}

fn put_row(vault: &crate::Vault, seed: u8, row: Value) -> Result<()> {
    put_policy_manifest_bytes(
        vault,
        test_id(seed),
        &encode_policy_manifest(vec![row_entry(row)]),
    )
}

#[test]
fn conversion_default_is_seeded_and_absent_fixture_stays_valid() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x30), &encode_policy_manifest(vec![]))?;
    let absent = resolve(&vault)?;
    assert_eq!(
        absent.project_conversion_policy(),
        Some(ProjectConversionPolicy::default())
    );
    let absent_hash = absent.read_frontier_hash()?;
    let (_tmp, vault) = temp_vault();
    put_row(
        &vault,
        0x30,
        conversion_row(
            "task_holder_then_source_leader",
            "inherit_source",
            4096,
            true,
        ),
    )?;
    let explicit = resolve(&vault)?;
    assert_eq!(
        explicit.project_conversion_policy(),
        Some(ProjectConversionPolicy::default())
    );
    assert_eq!(absent_hash, explicit.read_frontier_hash()?);
    let decoded = decode_policy_manifest(&default_policy_manifest()).expect("seeded policy parses");
    assert_eq!(
        decoded.project_conversion,
        Some(ProjectConversionPolicy::default())
    );
    Ok(())
}

#[test]
fn conversion_nondefault_and_multiple_manifests_narrow_with_frontier_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x30), &encode_policy_manifest(vec![]))?;
    let default_hash = resolve(&vault)?.read_frontier_hash()?;
    put_row(
        &vault,
        0x31,
        conversion_row("source_leader_only", "inherit_source", 8, true),
    )?;
    let first = resolve(&vault)?;
    let first_hash = first.read_frontier_hash()?;
    assert_ne!(default_hash, first_hash);
    assert_eq!(
        first.project_conversion_policy().expect("valid").max_tasks,
        8
    );
    put_row(
        &vault,
        0x32,
        conversion_row("task_holder_then_source_leader", "leader_only", 24, false),
    )?;
    let resolution = resolve(&vault)?;
    let policy = resolution.project_conversion_policy().expect("valid");
    assert_eq!(policy.leader_fallback, LeaderFallback::SourceLeaderOnly);
    assert_eq!(policy.roster_selection, RosterSelection::LeaderOnly);
    assert_eq!(policy.max_tasks, 8);
    assert!(!policy.allow_holder_override);
    assert_ne!(first_hash, resolution.read_frontier_hash()?);
    // Same trusted resolution may be called with the write transaction held.
    vault.with_write_txn(|txn| {
        assert_eq!(
            resolve_policy_manifest(&vault.store, txn)?.project_conversion_policy(),
            Some(policy)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn conversion_holder_override_is_bounded_to_actual_holder() {
    let leader = test_id(0x30);
    let holder = test_id(0x31);
    let outsider = test_id(0x32);
    let roster = vec![leader.to_hex()];
    let permissive = ProjectConversionPolicy::default();
    assert!(permissive.allows_leader_override(leader, &roster, None));
    assert!(permissive.allows_leader_override(holder, &roster, Some(holder)));
    assert!(!permissive.allows_leader_override(outsider, &roster, Some(holder)));
    assert!(!permissive.allows_leader_override(holder, &roster, None));
    let narrowed = permissive.restrict(ProjectConversionPolicy {
        allow_holder_override: false,
        ..permissive
    });
    assert!(!narrowed.allows_leader_override(holder, &roster, Some(holder)));
    assert!(narrowed.allows_leader_override(leader, &roster, Some(holder)));
}

#[test]
fn conversion_row_strict_parse_and_fail_closed_accessor() -> Result<()> {
    let mut bad_rows = vec![
        Value::from("not a map"),
        conversion_row("unknown", "inherit_source", 1, true),
        conversion_row("source_leader_only", "unknown", 1, true),
        conversion_row("source_leader_only", "inherit_source", 4097, true),
    ];
    let mut missing = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = missing else {
        unreachable!()
    };
    entries.pop();
    bad_rows.push(missing);
    let mut duplicate = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = duplicate else {
        unreachable!()
    };
    entries.push((Value::from("max_tasks"), Value::from(2_u64)));
    bad_rows.push(duplicate);
    let mut precedence = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = precedence else {
        unreachable!()
    };
    entries[0].1 = Value::from("last_writer_wins");
    bad_rows.push(precedence);
    let mut unknown = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = unknown else {
        unreachable!()
    };
    entries[0].0 = Value::from("bogus");
    bad_rows.push(unknown);
    let mut wrong_bool = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = wrong_bool else {
        unreachable!()
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("allow_holder_override"))
        .expect("bool row")
        .1 = Value::from("true");
    bad_rows.push(wrong_bool);
    let mut wrong_holder = conversion_row("source_leader_only", "inherit_source", 1, true);
    let Value::Map(ref mut entries) = wrong_holder else {
        unreachable!()
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("task_holder_fallback"))
        .expect("holder row")
        .1 = Value::from("owner_first");
    bad_rows.push(wrong_holder);
    for row in bad_rows {
        let (_tmp, vault) = temp_vault();
        put_row(&vault, 0x30, row)?;
        let resolved = resolve(&vault)?;
        assert!(resolved.diagnostics().malformed_manifest_seen);
        assert_eq!(resolved.project_conversion_policy(), None);
    }
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &encode_policy_manifest(vec![
            row_entry(conversion_row(
                "source_leader_only",
                "inherit_source",
                4,
                false,
            )),
            row_entry(conversion_row(
                "source_leader_only",
                "inherit_source",
                3,
                false,
            )),
        ]),
    )?;
    assert_eq!(resolve(&vault)?.project_conversion_policy(), None);
    Ok(())
}
