use super::*;

#[test]
fn pinned_stack_holds_across_auto_upgrade() {
    let v1 = stack("default-v1", "Default v1", 1, "2026-06-01");
    let v2 = stack(DEFAULT_MODEL_STACK_CURRENT_ID, "Default", 2, "2026-07-06");
    let before_upgrade =
        ModelStackRegistry::new(id("default-v1"), [v1.clone(), v2.clone()]).unwrap();
    let after_upgrade =
        ModelStackRegistry::new(id(DEFAULT_MODEL_STACK_CURRENT_ID), [v1, v2]).unwrap();
    let pinned = ModelStackPreference::pinned(id("default-v1"));

    let pinned_before = before_upgrade.resolve(&pinned, 120).unwrap();
    let pinned_after = after_upgrade.resolve(&pinned, 120).unwrap();
    let auto_after = after_upgrade
        .resolve(&ModelStackPreference::AutoUpgrade, 120)
        .unwrap();

    assert_eq!(pinned_before.stack.id.as_str(), "default-v1");
    assert_eq!(pinned_after.stack.id.as_str(), "default-v1");
    assert_eq!(auto_after.stack.id.as_str(), DEFAULT_MODEL_STACK_CURRENT_ID);
}

#[test]
fn compiled_default_registry_uses_versioned_current_id() {
    let registry = try_default_model_stack_registry().unwrap();

    assert_eq!(
        registry.current_default.as_str(),
        DEFAULT_MODEL_STACK_CURRENT_ID
    );
    assert!(registry.get(&id("default")).is_none());
}

#[test]
fn deprecation_countdown_advances() {
    let deprecation = ModelStackDeprecation::new(100, 130).unwrap();

    let scheduled = deprecation.status(90);
    let early_countdown = deprecation.status(110);
    let late_countdown = deprecation.status(125);
    let retired = deprecation.status(130);

    assert_eq!(scheduled.stage, ModelStackDeprecationStage::Scheduled);
    assert_eq!(scheduled.days_until_notice, Some(10));
    assert_eq!(scheduled.days_until_retirement, Some(40));
    assert_eq!(early_countdown.stage, ModelStackDeprecationStage::Countdown);
    assert_eq!(early_countdown.days_until_retirement, Some(20));
    assert_eq!(late_countdown.days_until_retirement, Some(5));
    assert_eq!(retired.stage, ModelStackDeprecationStage::Retired);
    assert_eq!(retired.days_until_retirement, None);
}

#[test]
fn stack_model_disclosure_resolves() {
    let registry = default_model_stack_registry();
    let disclosure = registry
        .disclose_stack(&id(DEFAULT_MODEL_STACK_CURRENT_ID), 20_641)
        .unwrap();

    let roles = disclosure
        .models
        .iter()
        .map(|model| (model.role.as_str(), model.model.as_str()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(disclosure.display_name, "Default");
    assert_eq!(
        roles.get("orchestrator").copied(),
        Some("oneiron/orchestrator-default@2026-07-06")
    );
    assert_eq!(
        roles.get("subagent").copied(),
        Some("oneiron/subagent-default@2026-07-06")
    );
    assert_eq!(
        roles.get("summarizer").copied(),
        Some("oneiron/summarizer-default@2026-07-06")
    );
}

#[test]
fn retired_pinned_stack_stops_serving() {
    let v1 = stack("default-v1", "Default v1", 1, "2026-06-01")
        .with_deprecation(ModelStackDeprecation::new(100, 130).unwrap());
    let registry = ModelStackRegistry::new(id("default-v1"), [v1]).unwrap();
    let pinned = ModelStackPreference::pinned(id("default-v1"));

    let err = registry.resolve(&pinned, 130).unwrap_err();

    assert!(matches!(err, ModelStackRegistryError::StackRetired { .. }));
}

#[test]
fn stack_rejects_unnormalized_roles() {
    let err = ModelStack::new(
        id("custom"),
        "Custom",
        1,
        vec![ModelStackModel::new(
            "orchestrator ",
            model("oneiron/orchestrator@2026-07-06"),
        )],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ModelStackRegistryError::UnnormalizedModelRole { .. }
    ));
}

#[test]
fn registry_deserialization_validates_shape() {
    let malformed = serde_json::json!({
        "current_default": "missing",
        "stacks": {
            "default-v2": {
                "id": "default-v2",
                "display_name": "Default",
                "generation": 2,
                "models": [
                    {
                        "role": "orchestrator",
                        "model": "oneiron/orchestrator@2026-07-06"
                    }
                ]
            }
        }
    });

    let err = serde_json::from_value::<ModelStackRegistry>(malformed).unwrap_err();

    assert!(err.to_string().contains("current default model stack"));
}

#[test]
fn model_stack_deserialization_rejects_empty_models() {
    let malformed = serde_json::json!({
        "id": "default-v2",
        "display_name": "Default",
        "generation": 2,
        "models": []
    });

    let err = serde_json::from_value::<ModelStack>(malformed).unwrap_err();

    assert!(err.to_string().contains("has no constituent models"));
}

#[test]
fn deprecation_deserialization_rejects_invalid_window() {
    let malformed = serde_json::json!({
        "notice_starts_epoch_day": 200,
        "retires_epoch_day": 100
    });

    let err = serde_json::from_value::<ModelStackDeprecation>(malformed).unwrap_err();

    assert!(err.to_string().contains("must start before retirement"));
}

#[test]
fn invalid_public_deprecation_window_does_not_underflow_status() {
    let invalid = ModelStackDeprecation {
        notice_starts_epoch_day: 200,
        retires_epoch_day: 100,
    };

    let status = invalid.status(150);

    assert_eq!(status.stage, ModelStackDeprecationStage::Retired);
    assert_eq!(status.days_until_notice, None);
    assert_eq!(status.days_until_retirement, None);
}

fn stack(id_value: &str, display_name: &str, generation: u32, revision: &str) -> ModelStack {
    ModelStack::new(
        id(id_value),
        display_name,
        generation,
        vec![
            ModelStackModel::new(
                "orchestrator",
                ModelId::new(format!("oneiron/orchestrator@{revision}")).unwrap(),
            ),
            ModelStackModel::new(
                "summarizer",
                ModelId::new(format!("oneiron/summarizer@{revision}")).unwrap(),
            ),
        ],
    )
    .unwrap()
}

fn id(value: &str) -> ModelStackId {
    ModelStackId::new(value).unwrap()
}

fn model(value: &str) -> ModelId {
    ModelId::new(value).unwrap()
}
