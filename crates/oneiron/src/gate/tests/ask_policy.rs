//! Ask operating rows: shipped defaults, strict overrides, and precedence.
use super::*;
use crate::gate::ask_policy::{AskOperationalPolicy, AskPolicyPrecedence, AskPolicySurface};

fn changed(f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Value {
    let Value::Map(mut entries) = AskOperationalPolicy::default_manifest_value() else {
        unreachable!()
    };
    f(&mut entries);
    Value::Map(entries)
}
fn field(rows: &mut [(Value, Value)], name: &str, value: Value) {
    rows.iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .expect("shipped key")
        .1 = value;
}
fn holder_row(holder: EntityId, limit: u64, surface: &str) -> Value {
    Value::Map(vec![
        ("holder_ref".into(), holder.to_hex().into()),
        ("guest_fact_limit".into(), limit.into()),
        ("surface".into(), surface.into()),
    ])
}
fn manifest(ask: Option<Value>) -> Vec<u8> {
    encode_policy_manifest(
        ask.map(|row| vec![(POLICY_ASK_POLICY_KEY.into(), row)])
            .unwrap_or_default(),
    )
}
#[test]
fn ask_manifest_ships_defaults_and_absent_override_matches() -> Result<()> {
    let shipped = decode_policy_manifest(&default_policy_manifest()).expect("default manifest");
    assert_eq!(shipped.ask_policy, Some(AskOperationalPolicy::default()));
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x45), &manifest(None))?;
    let resolved = resolve(&vault)?;
    let policy = resolved
        .ask_operational_policy()
        .expect("valid operating policy");
    assert_eq!(policy, AskOperationalPolicy::default());
    assert_eq!(policy.guest_limit_for(test_id(0x46), None), Some(16));
    assert_eq!(policy.retry_limit(usize::MAX), 64);
    assert_eq!(
        policy.surface_for(test_id(0x46), None),
        Some(AskPolicySurface::Card)
    );
    Ok(())
}
#[test]
fn ask_manifest_refuses_unknown_duplicate_and_holder_widen() {
    let holder = test_id(0x46);
    for row in [
        changed(|f| f.push(("future".into(), 1.into()))),
        changed(|f| f.push(("guest_fact_limit".into(), 7.into()))),
        changed(|f| field(f, "precedence", "unrecognized".into())),
        changed(|f| {
            field(
                f,
                "holder_overrides",
                Value::Array(vec![holder_row(holder, 17, "card")]),
            )
        }),
        changed(|f| field(f, "retry_page_limit", 0.into())),
    ] {
        assert!(decode_policy_manifest(&manifest(Some(row))).is_none());
    }
}
#[test]
fn ask_vault_caps_holder_and_class_with_row_backed_precedence() -> Result<()> {
    let holder = test_id(0x46);
    let (_tmp, vault) = temp_vault();
    let policy = changed(|f| {
        field(f, "guest_fact_limit", 24.into());
        field(f, "retry_page_limit", 7.into());
        field(
            f,
            "holder_overrides",
            Value::Array(vec![holder_row(holder, 9, "none")]),
        );
    });
    put_policy_manifest_bytes(&vault, test_id(0x45), &manifest(Some(policy)))?;
    let resolved = resolve(&vault)?;
    let policy = resolved.ask_operational_policy().unwrap();
    assert_eq!(policy.guest_limit_for(holder, Some(12)), Some(9));
    assert_eq!(policy.guest_limit_for(holder, Some(25)), None);
    assert_eq!(policy.retry_limit(999), 7);
    assert_eq!(
        policy.surface_for(holder, Some(AskPolicySurface::Card)),
        Some(AskPolicySurface::Card)
    );
    let hash = resolved.read_frontier_hash()?;
    drop(resolved);
    let alternate = changed(|f| {
        field(f, "guest_fact_limit", 24.into());
        field(f, "retry_page_limit", 7.into());
        field(f, "precedence", "holder_capped".into());
        field(
            f,
            "holder_overrides",
            Value::Array(vec![holder_row(holder, 9, "none")]),
        );
    });
    put_policy_manifest_bytes(&vault, test_id(0x45), &manifest(Some(alternate)))?;
    let resolved = resolve(&vault)?;
    let policy = resolved.ask_operational_policy().unwrap();
    assert_eq!(policy.precedence, AskPolicyPrecedence::HolderCapped);
    assert_eq!(
        policy.surface_for(holder, Some(AskPolicySurface::Card)),
        Some(AskPolicySurface::None)
    );
    assert_ne!(hash, resolved.read_frontier_hash()?);
    Ok(())
}
