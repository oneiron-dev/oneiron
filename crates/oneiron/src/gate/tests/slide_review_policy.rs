//! Shipped slide-review limits, scoped manifest narrowing, and strict row decode.
use super::*;
use crate::llm::decision::{SlideReviewLimits, SlideReviewPolicy};

fn limits(scope: &str, batch: u64, units: u64) -> Value {
    Value::Map(vec![
        ("scope".into(), scope.into()),
        ("batch_size".into(), batch.into()),
        ("max_units".into(), units.into()),
        ("max_text_bytes".into(), 2048_u64.into()),
        ("max_image_bytes".into(), 4096_u64.into()),
    ])
}
fn route(scope: &str, first: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        ("scope".into(), scope.into()),
        ("first".into(), first.into()),
        ("ceiling".into(), ceiling.into()),
    ])
}
fn precedence(mode: &str) -> Value {
    Value::Map(vec![
        ("scope".into(), "precedence".into()),
        ("value".into(), mode.into()),
    ])
}
fn holder(mut row: Value, id: EntityId) -> Value {
    let Value::Map(entries) = &mut row else {
        unreachable!()
    };
    entries.push(("holder".into(), id.to_hex().into()));
    row
}
fn entry(rows: Vec<Value>) -> (Value, Value) {
    ("slide_review_policy".into(), Value::Array(rows))
}

#[test]
fn shipped_rows_and_holder_rows_resolve_narrowly() -> Result<()> {
    let default = default_policy_manifest();
    let default_value = rmpv::decode::read_value(&mut default.as_slice()).unwrap();
    let Value::Map(entries) = default_value else {
        unreachable!()
    };
    let shipped = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("slide_review_policy"))
        .expect("shipped policy row")
        .1
        .clone();
    assert_eq!(
        SlideReviewPolicy::decode(&shipped)
            .unwrap()
            .resolve(test_id(0x52)),
        SlideReviewLimits::default()
    );
    let (_dir, vault) = support::temp_vault();
    let person = test_id(0x52);
    let rows = vec![
        precedence("holder_override_capped_at_vault"),
        limits("vault", 3, 10),
        route("route", "local", "big"),
        holder(limits("holder", 2, 5), person),
        holder(route("holder_route", "system_one", "system_one"), person),
    ];
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &support::encode_policy_manifest(vec![entry(rows)]),
    )?;
    let resolved = support::resolve(&vault)?;
    let (_baseline_dir, baseline) = support::temp_vault();
    put_policy_manifest_bytes(
        &baseline,
        test_id(0x30),
        &support::encode_policy_manifest(vec![]),
    )?;
    assert_ne!(
        resolved.read_frontier_hash()?,
        support::resolve(&baseline)?.read_frontier_hash()?
    );
    assert_eq!(resolved.slide_review_limits(person).unwrap().batch_size, 2);
    assert_eq!(resolved.slide_review_limits(person).unwrap().max_units, 5);
    assert_eq!(
        resolved
            .slide_review_limits(test_id(0x53))
            .unwrap()
            .batch_size,
        3
    );
    assert_eq!(
        resolved.slide_review_route(person).unwrap().first,
        crate::llm::decision::DecisionRung::SystemOne
    );
    assert_eq!(
        resolved.slide_review_route(test_id(0x53)).unwrap().first,
        crate::llm::decision::DecisionRung::Local
    );
    // A per-run request may narrow, not widen, the stored vault bound.
    assert_eq!(
        resolved
            .slide_review_limits(person)
            .unwrap()
            .restrict(SlideReviewLimits::default())
            .max_units,
        5
    );
    Ok(())
}

#[test]
fn malformed_or_widening_review_policy_fails_the_manifest_closed() -> Result<()> {
    for rows in [
        vec![precedence("unknown"), limits("vault", 3, 10)],
        vec![precedence("nested_narrowing"), limits("vault", 0, 10)],
        vec![precedence("nested_narrowing"), limits("vault", 9, 10)],
        vec![
            precedence("nested_narrowing"),
            limits("vault", 3, 10),
            limits("vault", 2, 5),
        ],
        vec![limits("vault", 3, 10)],
    ] {
        let (_dir, vault) = support::temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x30),
            &support::encode_policy_manifest(vec![entry(rows)]),
        )?;
        let resolved = support::resolve(&vault)?;
        assert!(resolved.slide_review_limits(test_id(0x52)).is_none());
        assert!(resolved.diagnostics().loaded_manifest_forces_fail_closed());
    }
    Ok(())
}

#[test]
fn contradictory_holder_and_vault_routes_fail_closed_across_manifests() -> Result<()> {
    let (_dir, vault) = support::temp_vault();
    let holder_id = test_id(0x52);
    let first = vec![
        precedence("nested_narrowing"),
        limits("vault", 8, 4096),
        route("route", "rule", "big"),
        holder(route("holder_route", "big", "big"), holder_id),
    ];
    let second = vec![
        precedence("nested_narrowing"),
        limits("vault", 8, 4096),
        route("route", "local", "local"),
    ];
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &support::encode_policy_manifest(vec![entry(first)]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &support::encode_policy_manifest(vec![entry(second)]),
    )?;
    let policy = support::resolve(&vault)?;
    assert!(policy.slide_review_route(holder_id).is_none());
    assert!(policy.diagnostics().loaded_manifest_forces_fail_closed());
    Ok(())
}
