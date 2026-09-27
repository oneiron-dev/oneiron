//! Residence operation budget manifest parsing and restrictive resolution tests.

use super::*;

const RESIDENCE_OPERATION_BUDGETS_KEY: &str = "residence_operation_budgets";

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn budget_row(vault: Value, holder: Option<Value>, precedence: Option<&str>) -> Value {
    let mut entries = Vec::new();
    if let Some(precedence) = precedence {
        entries.push(("precedence", Value::from(precedence)));
    }
    entries.push(("vault", vault));
    if let Some(holder) = holder {
        entries.push(("holder", holder));
    }
    map(entries)
}

fn manifest_with_budget(row: Value) -> Vec<u8> {
    encode_policy_manifest(vec![(Value::from(RESIDENCE_OPERATION_BUDGETS_KEY), row)])
}

fn put_budget_manifest(vault: &crate::Vault, seed: u8, row: Value) -> Result<()> {
    put_policy_manifest_bytes(vault, test_id(seed), &manifest_with_budget(row))
}

fn resolved_budgets(policy: &PolicyManifestResolution) -> ResidenceOperationBudgetLimits {
    policy
        .residence_operation_budgets()
        .expect("valid manifest policy exposes budgets")
}

#[test]
fn absent_and_empty_nested_maps_use_shipped_defaults() -> Result<()> {
    let (_tmp, absent_vault) = temp_vault();
    let absent = resolve(&absent_vault)?;
    let defaults = ResidenceOperationBudgetLimits::default();
    assert_eq!(resolved_budgets(&absent), defaults);

    let (_tmp, explicit_vault) = temp_vault();
    put_budget_manifest(&explicit_vault, 0x31, budget_row(map(vec![]), None, None))?;
    let explicit = resolve(&explicit_vault)?;
    assert_eq!(resolved_budgets(&explicit), defaults);
    assert_eq!(explicit.residence_operation_budgets(), Some(defaults));
    Ok(())
}

#[test]
fn budget_maps_are_closed_positive_bounded_and_duplicate_free() {
    let valid = budget_row(
        map(vec![("search_limit", Value::from(40_u64))]),
        Some(map(vec![("search_limit", Value::from(20_u64))])),
        None,
    );
    assert!(decode_policy_manifest(&manifest_with_budget(valid)).is_some());

    let invalid_rows = [
        budget_row(map(vec![("surprise", Value::from(1_u64))]), None, None),
        budget_row(map(vec![("search_limit", Value::from(0_u64))]), None, None),
        budget_row(
            map(vec![("search_limit", Value::from(101_u64))]),
            None,
            None,
        ),
        budget_row(
            map(vec![
                ("search_limit", Value::from(20_u64)),
                ("search_limit", Value::from(10_u64)),
            ]),
            None,
            None,
        ),
        budget_row(
            map(vec![]),
            Some(map(vec![("rpc_timeout_ms", Value::from(-1_i64))])),
            None,
        ),
        budget_row(map(vec![]), None, Some("widening")),
        budget_row(
            map(vec![(
                "index_cache_bytes",
                Value::from(32_u64 * 1024 * 1024 + 1),
            )]),
            None,
            None,
        ),
        map(vec![
            ("precedence", Value::from("nested_narrowing")),
            ("precedence", Value::from("nested_narrowing")),
            ("vault", map(vec![])),
        ]),
        map(vec![("vault", map(vec![])), ("vault", map(vec![]))]),
        map(vec![
            ("vault", map(vec![])),
            ("holder", map(vec![])),
            ("holder", map(vec![])),
        ]),
    ];
    for row in invalid_rows {
        assert!(
            decode_policy_manifest(&manifest_with_budget(row)).is_none(),
            "malformed residence budget row must reject its manifest"
        );
    }

    let duplicate_top_level = encode_policy_manifest(vec![
        (
            Value::from(RESIDENCE_OPERATION_BUDGETS_KEY),
            budget_row(map(vec![]), None, None),
        ),
        (
            Value::from(RESIDENCE_OPERATION_BUDGETS_KEY),
            budget_row(map(vec![]), None, None),
        ),
    ]);
    assert!(decode_policy_manifest(&duplicate_top_level).is_none());
}

#[test]
fn trusted_vault_and_holder_rows_compose_by_min_and_holder_cannot_widen() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_budget_manifest(
        &vault,
        0x32,
        budget_row(
            map(vec![
                ("rpc_timeout_ms", Value::from(9_000_u64)),
                ("index_page_limit", Value::from(200_u64)),
                ("max_index_pages", Value::from(200_u64)),
                ("current_window_count", Value::from(1_u64)),
                ("title_max_chars", Value::from(64_u64)),
                ("search_limit", Value::from(80_u64)),
                ("ack_timeout_ms", Value::from(10_000_u64)),
                ("index_cache_bytes", Value::from(8_u64 * 1024 * 1024)),
            ]),
            Some(map(vec![
                ("rpc_timeout_ms", Value::from(1_000_u64)),
                ("search_limit", Value::from(70_u64)),
                ("index_page_limit", Value::from(240_u64)),
            ])),
            Some("nested_narrowing"),
        ),
    )?;
    // A second vault-only row is restrictive and its absent holder map
    // inherits the vault value rather than widening the first holder limit.
    put_budget_manifest(
        &vault,
        0x33,
        budget_row(
            map(vec![
                ("search_limit", Value::from(75_u64)),
                ("index_page_limit", Value::from(180_u64)),
                ("max_index_pages", Value::from(150_u64)),
            ]),
            None,
            None,
        ),
    )?;
    // Replicated manifests are untrusted contributions and cannot tune these
    // operation limits, even when their values are more restrictive.
    let untrusted = manifest_with_budget(budget_row(
        map(vec![
            ("search_limit", Value::from(1_u64)),
            ("index_page_limit", Value::from(1_u64)),
        ]),
        Some(map(vec![("search_limit", Value::from(1_u64))])),
        None,
    ));
    vault
        .batch()
        .put_replicated(
            &test_id(0x34),
            crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
            test_time(1),
            1,
            &untrusted,
        )
        .commit()?;

    let policy = resolve(&vault)?;
    assert!(!policy.diagnostics().loaded_manifest_forces_fail_closed());
    let budgets = resolved_budgets(&policy);
    assert_eq!(budgets.rpc_timeout_ms, 1_000);
    assert_eq!(budgets.index_page_limit, 180);
    assert_eq!(budgets.max_index_pages, 150);
    assert_eq!(budgets.current_window_count, 1);
    assert_eq!(budgets.title_max_chars, 64);
    assert_eq!(budgets.search_limit, 70);
    assert_eq!(budgets.ack_timeout_ms, 10_000);
    assert_eq!(budgets.index_cache_bytes, 8 * 1024 * 1024);
    Ok(())
}

#[test]
fn malformed_loaded_budget_policy_has_no_budget_accessor_value() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_budget_manifest(
        &vault,
        0x35,
        budget_row(map(vec![("search_limit", Value::from(0_u64))]), None, None),
    )?;
    let policy = resolve(&vault)?;
    assert!(policy.diagnostics().loaded_manifest_forces_fail_closed());
    assert_eq!(policy.residence_operation_budgets(), None);
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn public_vault_accessor_returns_defaults_and_refuses_malformed_policy() -> Result<()> {
    let (_tmp, absent) = temp_vault();
    assert_eq!(
        absent.residence_operation_budgets()?,
        Some(crate::sync::residence_operation_budgets::ResidenceOperationBudgets::default())
    );

    let (_tmp, malformed) = temp_vault();
    put_budget_manifest(
        &malformed,
        0x36,
        budget_row(map(vec![("search_limit", Value::from(0_u64))]), None, None),
    )?;
    assert_eq!(malformed.residence_operation_budgets()?, None);
    Ok(())
}
