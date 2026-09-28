//! Failure-class rows are vault policy, not JSON fallback payload rules.
use super::*;
use crate::llm::{DreamerFailureClass, DreamerFailureRoute};

fn row(class: &str, route: &str, consolidation: bool, effector: bool) -> Value {
    Value::Map(vec![
        (Value::from("failure"), Value::from(class)),
        (Value::from("route"), Value::from(route)),
        (
            Value::from("consolidation_eligible"),
            Value::Boolean(consolidation),
        ),
        (Value::from("effector_eligible"), Value::Boolean(effector)),
        (
            Value::from("default_consolidation_eligible"),
            Value::Boolean(consolidation),
        ),
        (
            Value::from("default_effector_eligible"),
            Value::Boolean(effector),
        ),
    ])
}
fn manifest(rows: Vec<Value>) -> Vec<u8> {
    encode_policy_manifest(vec![(
        Value::from(POLICY_DREAMER_FAILURE_RULES_KEY),
        Value::Array(rows),
    )])
}

#[test]
fn resident_failure_classes_route_and_restrict_both_downstream_uses() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &manifest(vec![
            row("retryable", "retry", false, false),
            row("fatal", "fallback", true, false),
            row("budget", "budget_trap", false, false),
        ]),
    )?;
    let resolved = resolve(&vault)?;
    let fatal = resolved.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert_eq!(fatal.route, DreamerFailureRoute::Fallback);
    assert!(fatal.consolidation_eligible);
    assert!(!fatal.effector_eligible);
    assert!(fatal.consolidation_ceiling);
    assert!(!fatal.effector_ceiling);
    assert_eq!(
        resolved
            .dreamer_failure_decision(DreamerFailureClass::Retryable)
            .route,
        DreamerFailureRoute::Retry
    );
    assert_eq!(
        resolved
            .dreamer_failure_decision(DreamerFailureClass::Budget)
            .route,
        DreamerFailureRoute::BudgetTrap
    );
    // Another trusted pack can narrow, but cannot independently grant.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &manifest(vec![row("fatal", "fallback", false, true)]),
    )?;
    let narrowed = resolve(&vault)?.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(!narrowed.consolidation_eligible);
    assert!(!narrowed.effector_eligible);
    Ok(())
}

#[test]
fn missing_and_malformed_failure_rules_cannot_authorize_failed_output() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x30), &encode_policy_manifest(vec![]))?;
    let absent = resolve(&vault)?.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(!absent.consolidation_eligible && !absent.effector_eligible);
    assert!(!absent.consolidation_with_stage(Some(true)));
    assert!(!absent.effector_with_stage(Some(true)));
    for bad in [
        vec![row("unknown", "fallback", true, true)],
        vec![row("fatal", "retry", true, true)],
        vec![
            row("fatal", "fallback", true, true),
            row("fatal", "fallback", true, true),
        ],
        vec![Value::Map(vec![(
            Value::from("failure"),
            Value::from("fatal"),
        )])],
    ] {
        assert!(decode_policy_manifest(&manifest(bad)).is_none());
    }
    assert!(
        decode_policy_manifest(&encode_policy_manifest(vec![(
            Value::from(POLICY_DREAMER_FAILURE_PRECEDENCE_KEY),
            Value::from("unknown_precedence")
        ),]))
        .is_none()
    );
    Ok(())
}

fn shipped_policy_with(precedence: &str, consolidation_cap: bool, effector_cap: bool) -> Vec<u8> {
    let bytes = default_policy_manifest().unwrap();
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("manifest")
    else {
        panic!("manifest map")
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("dreamer_failure_precedence") {
            *value = precedence.into();
        }
        if key.as_str() == Some("dreamer_failure_rules") {
            let Value::Array(rows) = value else {
                panic!("default rows")
            };
            let Value::Map(fatal) = &mut rows[1] else {
                panic!("fatal row")
            };
            for (field, value) in fatal {
                match field.as_str() {
                    Some("consolidation_eligible") => *value = consolidation_cap.into(),
                    Some("effector_eligible") => *value = effector_cap.into(),
                    _ => {}
                }
            }
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode");
    out
}

#[test]
fn shipped_rows_default_to_no_failed_output_and_nested_narrowing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        default_policy_manifest_id()?,
        &default_policy_manifest().unwrap(),
    )?;
    let resolved = resolve(&vault)?;
    let decoded = decode_policy_manifest(&default_policy_manifest().unwrap()).expect("shipped policy");
    assert_eq!(decoded.dreamer_failure_rules.len(), 3);
    assert_eq!(
        decoded.dreamer_failure_precedence,
        Some(crate::llm::DreamerFailurePrecedence::NestedNarrowing)
    );
    let fatal = resolved.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(fatal.consolidation_ceiling && fatal.effector_ceiling);
    assert!(!fatal.consolidation_eligible && !fatal.effector_eligible);
    assert!(!fatal.consolidation_with_stage(Some(true)));
    assert!(!fatal.effector_with_stage(Some(true)));
    for class in [DreamerFailureClass::Retryable, DreamerFailureClass::Budget] {
        let row = resolved.dreamer_failure_decision(class);
        assert!(!row.consolidation_ceiling && !row.effector_ceiling);
        assert!(!row.consolidation_with_stage(Some(true)));
        assert!(!row.effector_with_stage(Some(true)));
    }
    Ok(())
}

#[test]
fn holder_override_remains_capped_and_concurrent_packs_narrow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = default_policy_manifest_id()?;
    put_policy_manifest_bytes(
        &vault,
        id,
        &shipped_policy_with("holder_override_capped_at_vault", true, true),
    )?;
    let decision = resolve(&vault)?.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(!decision.consolidation_eligible && !decision.effector_eligible);
    assert!(decision.consolidation_with_stage(Some(true)));
    assert!(decision.effector_with_stage(Some(true)));
    assert!(!decision.consolidation_with_stage(Some(false)));
    assert!(!decision.effector_with_stage(Some(false)));

    put_policy_manifest_bytes(
        &vault,
        id,
        &shipped_policy_with("holder_override_capped_at_vault", true, false),
    )?;
    let capped = resolve(&vault)?.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(capped.consolidation_with_stage(Some(true)));
    assert!(!capped.effector_with_stage(Some(true)));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &encode_policy_manifest(vec![
            (
                Value::from(POLICY_DREAMER_FAILURE_PRECEDENCE_KEY),
                Value::from("nested_narrowing"),
            ),
            (
                Value::from(POLICY_DREAMER_FAILURE_RULES_KEY),
                Value::Array(vec![row("fatal", "fallback", false, true)]),
            ),
        ]),
    )?;
    let narrowed = resolve(&vault)?.dreamer_failure_decision(DreamerFailureClass::Fatal);
    assert!(!narrowed.consolidation_with_stage(Some(true)));
    assert!(!narrowed.effector_with_stage(Some(true)));
    Ok(())
}
