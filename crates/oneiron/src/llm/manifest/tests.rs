use super::*;
use crate::llm::{CallClass, CallEnvelope, CallPurpose, ResponseFormat, TierPrecedence};
fn fixture() -> ModelManifest {
    ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: ModelId::new(format!("test/{role:?}@r1")).unwrap(),
                        slot: ModelSlot::Llm,
                        tier: ModelTierRef("configured".into()),
                    },
                )
            })
            .collect(),
        routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .into_iter()
            .map(|slot| (slot, ModelLocality::OwnServer))
            .collect(),
        verdict: None,
    }
}
#[test]
fn all_thirteen_roles_load_from_file_and_bind_with_narrow_vault_routes() {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let fixture = fixture();
    let path = dir.path().join("models.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let loaded = ModelManifest::load(&path).unwrap();
    assert_eq!(loaded, fixture);
    vault.set_model_manifest(&loaded).unwrap();
    vault
        .set_model_route(ModelSlot::Llm, ModelLocality::OnDevice)
        .unwrap();
    assert!(
        vault
            .set_model_route(ModelSlot::Llm, ModelLocality::ThirdParty)
            .is_err()
    );
    for role in MODEL_ROLES {
        let mut request = LlmRequest {
            model: ModelId::new("host/unused@1").unwrap(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Extraction,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("global".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::ThirdParty,
            },
            messages: vec![],
            tools: vec![],
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        vault.bind_model_role(role, &mut request).unwrap();
        assert_eq!(&request.model, &loaded.binding(role).unwrap().model);
        assert_eq!(request.envelope.locality, ModelLocality::OnDevice);
        assert_eq!(request.envelope.tier.resolved().as_str(), "configured");
    }
    let mut unknown = serde_json::to_value(fixture).unwrap();
    unknown["roles"]["bogus"] = unknown["roles"]["checker"].clone();
    assert!(ModelManifest::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
}
#[test]
fn floor_band_and_mode_fail_closed_without_granting() {
    let model = ModelId::new("test/checker@1").unwrap();
    let mut binding = VerdictBinding {
        model: model.clone(),
        slot: ModelSlot::Llm,
        floor: ConfidenceBand::High,
        mode: VerdictMode::Enforce,
    };
    let answer = CalibratedVerdict {
        model,
        allow: true,
        confidence_millionths: 700_000,
        band: ConfidenceBand::Medium,
        basis: VerdictBasis::CalibratedModel,
    };
    assert!(matches!(
        apply_verdict_floor(Some(&binding), AutoCheckOutcome::Verdict(answer.clone())).0,
        AutoCheckOutcome::Hold { .. }
    ));
    binding.mode = VerdictMode::Shadow;
    assert_eq!(
        apply_verdict_floor(Some(&binding), AutoCheckOutcome::Verdict(answer.clone())),
        (AutoCheckOutcome::Allow, Some("verdict_shadow_hold"))
    );
    let mut bad = answer;
    bad.band = ConfidenceBand::Certain;
    assert!(bad.validate().is_err());
    let mut manifest = serde_json::to_value(fixture()).unwrap();
    manifest["verdict"] =
        serde_json::json!({"model":"test/checker@1","slot":"llm","floor":0.9,"mode":"enforce"});
    assert!(ModelManifest::from_json(&serde_json::to_vec(&manifest).unwrap()).is_err());
}
