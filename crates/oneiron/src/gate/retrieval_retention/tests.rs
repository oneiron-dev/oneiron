use super::*;

fn limit_row(scope: &str, age: u64, runs: u64) -> Value {
    Value::Map(vec![
        ("scope".into(), scope.into()),
        ("max_age_secs".into(), age.into()),
        ("max_runs".into(), runs.into()),
    ])
}
fn precedence(order: &str) -> Value {
    Value::Map(vec![
        ("scope".into(), "precedence".into()),
        ("order".into(), order.into()),
    ])
}

#[test]
fn shipped_row_and_holder_compose_by_nested_narrowing() {
    let mut resolved = RetrievalRetentionPolicy::default();
    assert_eq!(
        resolved.effective(),
        (DEFAULT_RETRIEVAL_AGE_SECS, DEFAULT_RETRIEVAL_MAX_RUNS)
    );
    resolved.narrow(parse_retrieval_retention_rows(&default_retrieval_retention_rows()).unwrap());
    assert_eq!(
        resolved.effective(),
        (DEFAULT_RETRIEVAL_AGE_SECS, DEFAULT_RETRIEVAL_MAX_RUNS)
    );
    // Unlike a compiled max, the vault can author a different permitted cap.
    resolved.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("vault", DEFAULT_RETRIEVAL_AGE_SECS + 10, 2048),
            precedence("nested_narrowing"),
        ]))
        .unwrap(),
    );
    // Multiple manifests can only NARROW a previously resolved vault row.
    assert_eq!(
        resolved.effective(),
        (DEFAULT_RETRIEVAL_AGE_SECS, DEFAULT_RETRIEVAL_MAX_RUNS)
    );
    let mut changed_vault = RetrievalRetentionPolicy::default();
    changed_vault.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("vault", 20, 2048),
            precedence("nested_narrowing"),
        ]))
        .unwrap(),
    );
    assert_eq!(changed_vault.effective(), (20, 2048));
    changed_vault.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("holder", 10, 4096),
            precedence("nested_narrowing"),
        ]))
        .unwrap(),
    );
    assert_eq!(changed_vault.effective(), (10, 2048));
    changed_vault.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("holder", 5, 500),
            precedence("nested_narrowing"),
        ]))
        .unwrap(),
    );
    assert_eq!(changed_vault.effective(), (5, 500));

    let mut larger = RetrievalRetentionPolicy::default();
    larger.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("vault", 20, 65_536),
            precedence("nested_narrowing"),
        ]))
        .expect("representable authored capacity"),
    );
    larger.narrow(
        parse_retrieval_retention_rows(&Value::Array(vec![
            limit_row("holder", 20, 100_000),
            precedence("nested_narrowing"),
        ]))
        .expect("holder request over vault ceiling"),
    );
    assert_eq!(larger.effective(), (20, 65_536));
}

#[test]
fn malformed_retention_rows_fail_closed_at_manifest_decode() {
    for bad in [
        Value::Array(vec![limit_row("vault", 1, 10)]),
        Value::Array(vec![
            limit_row("vault", 1, 10),
            precedence("last_writer_wins"),
        ]),
        Value::Array(vec![
            limit_row("vault", 1, 10),
            limit_row("vault", 2, 20),
            precedence("nested_narrowing"),
        ]),
        Value::Array(vec![
            limit_row("holder", 0, 2),
            precedence("nested_narrowing"),
        ]),
    ] {
        assert!(parse_retrieval_retention_rows(&bad).is_none(), "{bad:?}");
    }
}
