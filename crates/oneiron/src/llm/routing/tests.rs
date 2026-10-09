use super::*;

fn model(value: &str) -> ModelId {
    ModelId::new(value).unwrap()
}
fn policy() -> DescriptionPolicy {
    DescriptionPolicy {
        models: vec![
            ModelDescription {
                model: model("test/cheap@r1"),
                wire: ModelWireFormat::OpenaiCompat,
                locality: ModelLocality::OnDevice,
                owner: Some(OwnerModelLine {
                    model: model("test/cheap@r1"),
                    text: "small fast tasks".into(),
                    expected_quality: 800_000,
                }),
                public_benchmark: Some("public cheap".into()),
                vendor: None,
                effort_ladder: vec![ReasoningEffort::Low, ReasoningEffort::High],
            },
            ModelDescription {
                model: model("test/strong@r1"),
                wire: ModelWireFormat::OpenaiCompat,
                locality: ModelLocality::OwnServer,
                owner: Some(OwnerModelLine {
                    model: model("test/strong@r1"),
                    text: "deep tasks".into(),
                    expected_quality: 900_000,
                }),
                public_benchmark: None,
                vendor: None,
                effort_ladder: vec![ReasoningEffort::Low, ReasoningEffort::High],
            },
        ],
        contradiction_margin_millionths: 100_000,
        vault_effort: None,
        purpose_effort: BTreeMap::new(),
        global_effort: None,
    }
}

#[test]
fn persisted_reask_is_recoverable_after_restart_until_acknowledged() {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let mut configured = policy();
    configured.models[1].model = model("test/strong@r2");
    vault.set_description_policy(&configured).unwrap();
    let original = vault.check_description_drift().unwrap();
    assert_eq!(original.len(), 1);
    drop(vault); // simulate a crash before the host has queued the owner ask
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert!(reopened.check_description_drift().unwrap().is_empty());
    assert_eq!(reopened.pending_description_reasks().unwrap(), original);
    reopened
        .acknowledge_description_reask(&original[0].identity)
        .unwrap();
    assert!(reopened.pending_description_reasks().unwrap().is_empty());
    assert!(reopened.check_description_drift().unwrap().is_empty());
    assert!(
        reopened
            .description_reask(&original[0].identity)
            .unwrap()
            .unwrap()
            .acknowledged
    );
}
