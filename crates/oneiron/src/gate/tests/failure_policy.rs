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
    assert!(fatal.manifest_restricts);
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
    assert!(
        !absent.manifest_restricts,
        "no row cannot veto a separate authored stage rule"
    );
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
    Ok(())
}
