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
        seat_policy: None,
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

fn set_teacher_probe_policy_row(vault: &Vault, minimum: u64, holder: Option<(&str, u64)>) {
    let bytes = crate::gate::default_policy_manifest().unwrap();
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
fn widened_resident_route_is_refused_at_inference_admission() {
    let (_dir, vault) = policy_vault();
    let manifest = fixture();
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
        vault.set_model_route(ModelSlot::Llm, ModelLocality::ThirdParty),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(
        vault.model_route(ModelSlot::Llm).unwrap(),
        Some(ModelLocality::OwnServer)
    );

    // Corrupt resident storage as an untrusted writer could; bypass only the setter.
    vault
        .with_write_txn(|txn| {
            RESIDENT_ROUTES.put(
                &vault.store,
                txn,
                &(),
                &BTreeMap::from([(ModelSlot::Llm, ModelLocality::ThirdParty)]),
            )
        })
        .unwrap();
    let request = LlmRequest {
        model: ModelId::new("host/unused@1").unwrap(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let host = crate::llm::HostInferenceContext {
        binding: crate::llm::HostInferenceBinding::Advertised {
            model: manifest.binding(ModelRole::Checker).unwrap().model.clone(),
            locality: ModelLocality::ThirdParty,
        },
        extraction_egress: None,
    };
    assert!(matches!(
        vault.model_route(ModelSlot::Llm),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        vault.authorize_model_role(ModelRole::Checker, request, &host),
        Err(Error::InvalidConfig(_))
    ));
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
            seat_effort: None,
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
        host_segments: None,
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
