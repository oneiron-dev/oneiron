use super::*;
use crate::llm::{CallClass, CallEnvelope, CallPurpose, ResponseFormat, TierPrecedence};
fn policy_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    (dir, vault)
}

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
                        route_models: if role == ModelRole::ExtractionTeacher {
                            BTreeMap::new()
                        } else {
                            BTreeMap::from([(
                                ModelLocality::OnDevice,
                                ModelId::new(format!("local/{role:?}@r1")).unwrap(),
                            )])
                        },
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
fn teacher_pin_requires_matching_passing_probe_at_the_vault_write_door() {
    let (_dir, vault) = policy_vault();
    let original = fixture();
    assert!(matches!(
        vault.set_model_manifest(&original),
        Err(Error::InvalidConfig(_))
    ));
    assert!(vault.model_manifest().unwrap().is_none());
    assert!(
        TeacherProbeApproval::for_scored_checkpoint(
            &original,
            &vault.teacher_probe_policy(None).unwrap(),
            799_999
        )
        .is_err()
    );
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &original,
        &vault.teacher_probe_policy(None).unwrap(),
        800_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&original, &approval)
        .unwrap();
    assert_eq!(vault.model_manifest().unwrap(), Some(original.clone()));

    let mut changed = original.clone();
    changed
        .roles
        .get_mut(&ModelRole::ExtractionTeacher)
        .unwrap()
        .model = ModelId::new("new/untested@r2").unwrap();
    assert!(vault.set_model_manifest(&changed).is_err());
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&changed, &approval)
            .is_err()
    );
    assert_eq!(vault.model_manifest().unwrap(), Some(original));

    let mut bad_score = approval;
    bad_score.f1_millionths = 799_999;
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&changed, &bad_score)
            .is_err()
    );
    let next = TeacherProbeApproval::for_scored_checkpoint(
        &changed,
        &vault.teacher_probe_policy(None).unwrap(),
        900_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&changed, &next)
        .unwrap();
    assert_eq!(vault.model_manifest().unwrap(), Some(changed.clone()));

    // Other role updates do not need another teacher probe.
    changed.roles.get_mut(&ModelRole::Checker).unwrap().model =
        ModelId::new("test/new-checker@r1").unwrap();
    vault.set_model_manifest(&changed).unwrap();
    assert_eq!(vault.model_manifest().unwrap(), Some(changed.clone()));

    changed
        .roles
        .get_mut(&ModelRole::ExtractionTeacher)
        .unwrap()
        .route_models
        .insert(
            ModelLocality::OnDevice,
            ModelId::new("local/untested@r1").unwrap(),
        );
    assert!(vault.set_model_manifest(&changed).is_err());
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&changed, &next)
            .is_err()
    );
}

#[test]
fn teacher_policy_stricter_vault_bar_refuses_old_eighty_five_percent_approval() {
    let (_dir, vault) = policy_vault();
    let manifest = fixture();
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None).unwrap(),
        850_000,
    )
    .unwrap();
    let bytes = crate::gate::default_policy_manifest();
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).unwrap() else {
        panic!("default policy must be a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("teacher_probe"));
    entries.push((
        rmpv::Value::from("teacher_probe"),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("probe_id"),
                rmpv::Value::from(TEACHER_PROBE_ID),
            ),
            (
                rmpv::Value::from("min_f1_millionths"),
                rmpv::Value::from(900_000_u64),
            ),
        ]),
    ));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &encoded,
    )
    .unwrap();
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&manifest, &approval)
            .is_err()
    );
    assert!(vault.model_manifest().unwrap().is_none());
    let stricter = vault.teacher_probe_policy(None).unwrap();
    assert_eq!(stricter.min_f1_millionths, 900_000);
    assert!(TeacherProbeApproval::for_scored_checkpoint(&manifest, &stricter, 850_000).is_err());
    let accepted =
        TeacherProbeApproval::for_scored_checkpoint(&manifest, &stricter, 950_000).unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &accepted)
        .unwrap();
    assert_eq!(vault.model_manifest().unwrap(), Some(manifest));
}

fn set_teacher_probe_policy_row(vault: &Vault, minimum: u64, holder: Option<(&str, u64)>) {
    let bytes = crate::gate::default_policy_manifest();
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap()
    else {
        panic!("seeded manifest is a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("teacher_probe"));
    let holders = holder
        .map(|(id, floor)| {
            vec![rmpv::Value::Map(vec![
                (rmpv::Value::from("holder_ref"), rmpv::Value::from(id)),
                (
                    rmpv::Value::from("min_f1_millionths"),
                    rmpv::Value::from(floor),
                ),
            ])]
        })
        .unwrap_or_default();
    entries.push((
        rmpv::Value::from("teacher_probe"),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("probe_id"),
                rmpv::Value::from(TEACHER_PROBE_ID),
            ),
            (
                rmpv::Value::from("min_f1_millionths"),
                rmpv::Value::from(minimum),
            ),
            (rmpv::Value::from("holders"), rmpv::Value::Array(holders)),
        ]),
    ));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &encoded,
    )
    .unwrap();
}

#[test]
fn teacher_policy_holder_cannot_loosen_parent_and_old_receipts_cannot_silently_reuse() {
    let (_dir, vault) = policy_vault();
    let holder = "77777777777777777777777777777777";
    let manifest = fixture();
    let initial = vault.teacher_probe_policy(None).unwrap();
    assert_eq!(initial.vault_min_f1_millionths, 800_000);
    let previous =
        TeacherProbeApproval::for_scored_checkpoint(&manifest, &initial, 950_000).unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &previous)
        .unwrap();
    set_teacher_probe_policy_row(&vault, 900_000, Some((holder, 800_000)));
    assert!(vault.teacher_probe_policy(Some(holder)).is_err());
    assert!(vault.set_model_manifest(&manifest).is_err());
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&manifest, &previous)
            .is_err()
    );

    set_teacher_probe_policy_row(&vault, 900_000, Some((holder, 950_000)));
    let changed = vault.teacher_probe_policy(Some(holder)).unwrap();
    assert_eq!(changed.vault_min_f1_millionths, 900_000);
    assert_eq!(changed.min_f1_millionths, 950_000);
    // 0.95 was enough for either policy's numeric bar; the old receipt is
    // still stale because its resolved policy identity changed.
    assert!(
        vault
            .set_model_manifest_with_teacher_approval(&manifest, &previous)
            .is_err()
    );
    let current =
        TeacherProbeApproval::for_scored_checkpoint(&manifest, &changed, 950_000).unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &current)
        .unwrap();
    assert!(vault.set_model_manifest(&manifest).is_ok());

    set_teacher_probe_policy_row(&vault, 920_000, Some((holder, 960_000)));
    assert!(vault.set_model_manifest(&manifest).is_err());
    let stricter = vault.teacher_probe_policy(Some(holder)).unwrap();
    assert!(TeacherProbeApproval::for_scored_checkpoint(&manifest, &stricter, 950_000).is_err());
    let refreshed =
        TeacherProbeApproval::for_scored_checkpoint(&manifest, &stricter, 970_000).unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &refreshed)
        .unwrap();
}

#[test]
fn all_thirteen_roles_load_from_file_and_bind_with_narrow_vault_routes() {
    let (dir, vault) = policy_vault();
    let fixture = fixture();
    let path = dir.path().join("models.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let loaded = ModelManifest::load(&path).unwrap();
    assert_eq!(loaded, fixture);
    assert!(vault.set_model_manifest(&loaded).is_err());
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &loaded,
        &vault.teacher_probe_policy(None).unwrap(),
        1_000_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&loaded, &approval)
        .unwrap();
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
                scope: Default::default(),
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
        if role == ModelRole::ExtractionTeacher {
            // Narrowing a served slot may succeed, but must never send a
            // transcript through the teacher's wider, probed checkpoint.
            let host = super::super::HostInferenceContext {
                binding: super::super::HostInferenceBinding::Advertised {
                    model: loaded.binding(role).unwrap().model.clone(),
                    locality: ModelLocality::OnDevice,
                },
                extraction_egress: None,
            };
            assert!(matches!(
                vault.authorize_model_role(role, request, &host),
                Err(Error::InvalidConfig(_))
            ));
            continue;
        }
        let local_model =
            loaded.binding(role).unwrap().route_models[&ModelLocality::OnDevice].clone();
        vault
            .put_model_registry_row(&super::super::registry::ModelRegistryRow {
                version: 1,
                wire: super::super::registry::ModelWireFormat::Local,
                catalog: super::super::LlmCatalogEntry {
                    model: local_model.clone(),
                    display_name: "local fixture".into(),
                    locality: ModelLocality::OnDevice,
                    context_window_tokens: 4096,
                    max_output_tokens: Some(100),
                    cost: Some(super::super::LlmCatalogCost {
                        input_per_million: "0".into(),
                        output_per_million: "0".into(),
                        cache_read_per_million: None,
                        cache_write_per_million: None,
                    }),
                    capabilities: vec![],
                    metadata: BTreeMap::new(),
                },
                scores: BTreeMap::new(),
                fetched_at: BTreeMap::new(),
            })
            .unwrap();
        let host = super::super::HostInferenceContext {
            binding: super::super::HostInferenceBinding::Advertised {
                model: local_model,
                locality: ModelLocality::OnDevice,
            },
            extraction_egress: None,
        };
        request = vault
            .authorize_model_role(role, request, &host)
            .unwrap()
            .into_request();
        assert_eq!(
            &request.model,
            &loaded.binding(role).unwrap().route_models[&ModelLocality::OnDevice]
        );
        let catalog = crate::llm::LlmCatalogEntry {
            model: request.model.clone(),
            display_name: "local fixture".into(),
            locality: ModelLocality::OnDevice,
            context_window_tokens: 4096,
            max_output_tokens: Some(100),
            cost: None,
            capabilities: vec![],
            metadata: BTreeMap::new(),
        };
        catalog.admit(&request, false).unwrap();
        assert_eq!(request.envelope.locality, catalog.locality);
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

#[test]
fn verdict_modes_preserve_legacy_refusals_and_reasons() {
    for mode in [VerdictMode::Shadow, VerdictMode::Enforce] {
        let binding = VerdictBinding {
            model: ModelId::new("test/checker@1").unwrap(),
            slot: ModelSlot::Llm,
            floor: ConfidenceBand::High,
            mode,
        };
        for outcome in [
            AutoCheckOutcome::Unavailable,
            AutoCheckOutcome::Hold {
                reasons: vec!["host_policy".into(), "missing_evidence".into()],
            },
        ] {
            assert_eq!(
                apply_verdict_floor(Some(&binding), outcome.clone()),
                (outcome, None)
            );
        }
    }
}

#[test]
fn narrowing_without_a_distinct_model_is_refused_without_relabeling() {
    let (_dir, vault) = policy_vault();
    let mut manifest = fixture();
    manifest
        .roles
        .get_mut(&ModelRole::Checker)
        .unwrap()
        .route_models
        .clear();
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None).unwrap(),
        1_000_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .unwrap();
    assert!(matches!(
        vault.set_model_route(ModelSlot::Llm, ModelLocality::OnDevice),
        Err(Error::InvalidConfig(_))
    ));
    let mut request = LlmRequest {
        model: ModelId::new("host/model@1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let before = request.clone();
    let routes = BTreeMap::from([(ModelSlot::Llm, ModelLocality::OnDevice)]);
    assert!(
        manifest
            .bind_request(ModelRole::Checker, &routes, &mut request)
            .is_err()
    );
    assert_eq!(request, before);
    let host = super::super::HostInferenceContext {
        binding: super::super::HostInferenceBinding::Advertised {
            model: manifest.binding(ModelRole::Checker).unwrap().model.clone(),
            locality: ModelLocality::OwnServer,
        },
        extraction_egress: None,
    };
    request = vault
        .authorize_model_role(ModelRole::Checker, request, &host)
        .unwrap()
        .into_request();
    assert_eq!(
        request.model,
        manifest.binding(ModelRole::Checker).unwrap().model
    );
    assert_eq!(request.envelope.locality, ModelLocality::OwnServer);
    let checker = manifest.roles.get_mut(&ModelRole::Checker).unwrap();
    checker
        .route_models
        .insert(ModelLocality::OnDevice, checker.model.clone());
    assert!(manifest.validate().is_err());
}
