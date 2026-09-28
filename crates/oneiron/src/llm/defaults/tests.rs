//! Purpose policy and binding regressions.
use super::super::{
    LlmCatalogCost, LlmCatalogEntry,
    registry::{ModelRegistryRow, ModelWireFormat},
};
use super::*;
fn bind(
    vault: &Vault,
    role: super::super::manifest::ModelRole,
    request: &mut super::super::LlmRequest,
    egress: Option<&dyn ExtractionEgressPredicate>,
) -> Result<()> {
    let host = super::super::HostInferenceContext {
        binding: super::super::HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality: request.envelope.locality,
        },
        extraction_egress: egress,
    };
    let authorized = vault.authorize_model_role(role, request.clone(), &host)?;
    *request = authorized.into_request();
    Ok(())
}

#[test]
fn every_builtin_resolves_to_its_policy_without_overriding_the_vault() {
    let table = PurposeDefaultTable::default();
    table.validate().unwrap();
    let expected = [
        (
            CallPurpose::Extraction,
            "extraction",
            ModelLocality::OnDevice,
        ),
        (
            CallPurpose::Consolidation,
            "consolidation",
            ModelLocality::OwnServer,
        ),
        (CallPurpose::AnswerGen, "answer", ModelLocality::OnDevice),
        (CallPurpose::AutoCheck, "cheap", ModelLocality::OwnServer),
        (
            CallPurpose::ToolRouting,
            "tiny-fast",
            ModelLocality::OnDevice,
        ),
        (CallPurpose::Voice, "voice", ModelLocality::OnDevice),
        (CallPurpose::Eval, "eval-pinned", ModelLocality::OnDevice),
    ];
    for (purpose, tier_name, locality) in expected {
        let row = table.purpose(&purpose).unwrap();
        assert_eq!(row.tier.as_str(), tier_name);
        assert_eq!(row.locality, locality);
        let mut tier = table.precedence(&purpose, ModelTierRef("global".into()));
        assert_eq!(tier.resolved(), &row.tier);
        tier.vault_policy = Some(ModelTierRef("vault".into()));
        let mut envelope = CallEnvelope {
            scope: Default::default(),
            purpose,
            class: super::super::CallClass::BestEffort,
            tier,
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        };
        table.apply(&mut envelope);
        // A default cannot relabel an already selected host/model route.
        assert_eq!(envelope.locality, ModelLocality::ThirdParty);
        assert_eq!(envelope.tier.resolved().as_str(), "vault");
    }
    assert!(
        table
            .purpose(&CallPurpose::Other {
                name: "custom".into()
            })
            .is_none()
    );
}

#[test]
fn resident_rows_roundtrip_and_change_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let mut table = vault.purpose_default_table().unwrap();
    assert_eq!(
        table.voice(VoiceLane::AsrLive).locality,
        ModelLocality::ThirdParty
    );
    assert_eq!(
        table.voice(VoiceLane::AsrBatch).locality,
        ModelLocality::OwnServer
    );
    assert_eq!(
        table.voice(VoiceLane::TtsLive).locality,
        ModelLocality::OwnServer
    );
    assert_eq!(
        table.voice(VoiceLane::TtsBatch).locality,
        ModelLocality::OwnServer
    );
    table
        .purposes
        .get_mut(&CallPurpose::AnswerGen)
        .unwrap()
        .tier = ModelTierRef("resident-answer".into());
    table.voice.get_mut(&VoiceLane::AsrLive).unwrap().tier = ModelTierRef("resident-asr".into());
    vault.set_purpose_default_table(&table).unwrap();
    let loaded = vault.purpose_default_table().unwrap();
    assert_eq!(loaded, table);
    assert_eq!(
        loaded
            .precedence(&CallPurpose::AnswerGen, ModelTierRef("global".into()))
            .resolved()
            .as_str(),
        "resident-answer"
    );
    let mut envelope = CallEnvelope {
        scope: Default::default(),
        purpose: CallPurpose::AnswerGen,
        class: super::super::CallClass::BestEffort,
        tier: TierPrecedence::for_purpose(&CallPurpose::AnswerGen, ModelTierRef("global".into())),
        response_format: super::super::ResponseFormat::Text,
        locality: ModelLocality::ThirdParty,
    };
    vault.apply_purpose_defaults(&mut envelope).unwrap();
    assert_eq!(envelope.tier.resolved().as_str(), "resident-answer");
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .tier = ModelTierRef("resident-consolidation".into());
    vault.set_purpose_default_table(&table).unwrap();
    let mut request = super::super::LlmRequest {
        model: super::super::ModelId::new("test/model@r1").unwrap(),
        envelope: CallEnvelope {
            purpose: CallPurpose::Consolidation,
            locality: ModelLocality::OwnServer,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            ..envelope
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    bind(
        &vault,
        super::super::manifest::ModelRole::GenerativeReasoner,
        &mut request,
        None,
    )
    .unwrap();
    assert_eq!(
        request.envelope.tier.resolved().as_str(),
        "resident-consolidation"
    );
    let mut incomplete = table.clone();
    incomplete.purposes.remove(&CallPurpose::Eval);
    assert!(vault.set_purpose_default_table(&incomplete).is_err());
    assert_eq!(vault.purpose_default_table().unwrap(), table);
    let mut nonlocal = table;
    nonlocal
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .unwrap()
        .locality = ModelLocality::OwnServer;
    // A route outside the owner-authored egress bound cannot be stored.
    assert!(matches!(
        vault.set_purpose_default_table(&nonlocal),
        Err(Error::InvalidConfig(_))
    ));
    nonlocal.extraction_max_locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&nonlocal).unwrap();
    assert_eq!(vault.purpose_default_table().unwrap(), nonlocal);
    // An approved resident may narrow rows but cannot widen the owner pin.
    let mut wider = nonlocal.clone();
    wider.extraction_max_locality = ModelLocality::ThirdParty;
    assert!(matches!(
        vault.set_resident_purpose_default_table(&wider),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn four_voice_lanes_select_concrete_backends_and_resident_edits_take_effect() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let lanes = [
        VoiceLane::AsrLive,
        VoiceLane::AsrBatch,
        VoiceLane::TtsLive,
        VoiceLane::TtsBatch,
    ];
    let table = vault.purpose_default_table().unwrap();
    let mut candidates = vec![];
    for (index, lane) in lanes.iter().enumerate() {
        let row = table.voice(*lane);
        candidates.push(VoiceBackendBinding {
            model: ModelId::new(format!("test/voice-{index}@r1")).unwrap(),
            tier: row.tier.clone(),
            locality: row.locality,
        });
    }
    let mut delivered = vec![];
    for (lane, expected) in lanes.iter().zip(&candidates) {
        let selected = vault
            .select_voice_backend(*lane, None, &candidates)
            .unwrap();
        delivered.push(selected.model.clone());
        assert_eq!(&selected, expected);
    }
    assert_eq!(
        delivered,
        candidates
            .iter()
            .map(|candidate| candidate.model.clone())
            .collect::<Vec<_>>()
    );
    let mut edited = table;
    edited.voice.get_mut(&VoiceLane::AsrLive).unwrap().tier = ModelTierRef("resident-live".into());
    vault.set_purpose_default_table(&edited).unwrap();
    assert!(
        vault
            .select_voice_backend(VoiceLane::AsrLive, None, &candidates)
            .is_err()
    );
    let custom = VoiceBackendBinding {
        model: ModelId::new("test/resident-asr@r1").unwrap(),
        tier: ModelTierRef("resident-live".into()),
        locality: ModelLocality::ThirdParty,
    };
    candidates.push(custom.clone());
    assert_eq!(
        vault
            .select_voice_backend(VoiceLane::AsrLive, None, &candidates)
            .unwrap(),
        custom
    );
    // An authenticated per-call/manifest policy has higher precedence.
    let explicit = PurposeDefault {
        tier: ModelTierRef("asr-live".into()),
        locality: ModelLocality::ThirdParty,
    };
    assert_eq!(
        vault
            .select_voice_backend(VoiceLane::AsrLive, Some(&explicit), &candidates)
            .unwrap(),
        candidates[0]
    );
}

#[test]
fn voice_precedence_is_editable_but_override_cannot_widen_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let mut table = vault.purpose_default_table().unwrap();
    table.voice.get_mut(&VoiceLane::AsrLive).unwrap().locality = ModelLocality::OnDevice;
    table.voice.get_mut(&VoiceLane::AsrLive).unwrap().tier = ModelTierRef("local-asr".into());
    vault.set_purpose_default_table(&table).unwrap();
    let remote = PurposeDefault {
        tier: ModelTierRef("remote-asr".into()),
        locality: ModelLocality::ThirdParty,
    };
    let local = PurposeDefault {
        tier: ModelTierRef("alternate-local".into()),
        locality: ModelLocality::OnDevice,
    };
    let available = [
        VoiceBackendBinding {
            model: ModelId::new("test/remote@r1").unwrap(),
            tier: remote.tier.clone(),
            locality: remote.locality,
        },
        VoiceBackendBinding {
            model: ModelId::new("test/default-local@r1").unwrap(),
            tier: ModelTierRef("local-asr".into()),
            locality: ModelLocality::OnDevice,
        },
        VoiceBackendBinding {
            model: ModelId::new("test/override-local@r1").unwrap(),
            tier: local.tier.clone(),
            locality: local.locality,
        },
    ];
    assert!(matches!(
        vault.select_voice_backend(VoiceLane::AsrLive, Some(&remote), &available),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(
        vault
            .select_voice_backend(VoiceLane::AsrLive, Some(&local), &available)
            .unwrap(),
        available[2]
    );
    table.voice_precedence = VoicePrecedence::VaultOnly;
    vault.set_purpose_default_table(&table).unwrap();
    assert_eq!(
        vault
            .select_voice_backend(VoiceLane::AsrLive, Some(&local), &available)
            .unwrap(),
        available[1]
    );
    let stored = vault.purpose_default_table().unwrap();
    assert_eq!(stored.voice_precedence, VoicePrecedence::VaultOnly);
    let mut resident = stored;
    resident.voice_precedence = VoicePrecedence::NestedNarrowing;
    assert!(matches!(
        vault.set_resident_purpose_default_table(&resident),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn nonlocal_extraction_without_stored_table_still_requires_host_egress() {
    use super::super::{CallClass, LlmRequest};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let mut request = LlmRequest {
        model: ModelId::new("test/remote@r1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("global".into()),
            ),
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    let prior = request.clone();
    let allow = |_: &LlmRequest| true;
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::ExtractionTeacher,
            &mut request,
            Some(&allow)
        ),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(request, prior);
}

#[test]
fn nonlocal_extraction_requires_host_egress_verdict_before_binding() {
    use super::super::{CallClass, LlmRequest};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let mut table = vault.purpose_default_table().unwrap();
    table.extraction_max_locality = ModelLocality::OwnServer;
    table
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .unwrap()
        .locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&table).unwrap();
    let mut request = LlmRequest {
        model: ModelId::new("test/own-extraction@r1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("global".into()),
            ),
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    let prior = request.clone();
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::ExtractionTeacher,
            &mut request,
            None
        ),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(request, prior);
    let deny = |_: &LlmRequest| false;
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::ExtractionTeacher,
            &mut request,
            Some(&deny)
        ),
        Err(Error::InvalidConfig(_))
    ));
    let allow = |call: &LlmRequest| {
        call.model == prior.model && call.envelope.locality == ModelLocality::OwnServer
    };
    bind(
        &vault,
        super::super::manifest::ModelRole::ExtractionTeacher,
        &mut request,
        Some(&allow),
    )
    .unwrap();
    assert_eq!(request.model, prior.model);
    assert_eq!(request.envelope.locality, ModelLocality::OwnServer);
}

#[test]
fn registered_local_model_binds_under_stored_local_default_without_a_manifest() {
    use super::super::{CallClass, LlmCatalogCost, LlmCatalogEntry, LlmRequest};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let model = ModelId::new("local/consolidation@r1").unwrap();
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::Local,
            catalog: LlmCatalogEntry {
                model: model.clone(),
                display_name: "local consolidation".into(),
                locality: ModelLocality::OnDevice,
                context_window_tokens: 4096,
                max_output_tokens: None,
                cost: Some(LlmCatalogCost {
                    input_per_million: "0".into(),
                    output_per_million: "0".into(),
                    cache_read_per_million: None,
                    cache_write_per_million: None,
                }),
                capabilities: vec![],
                metadata: Default::default(),
            },
            scores: Default::default(),
            fetched_at: Default::default(),
        })
        .unwrap();
    let mut table = vault.purpose_default_table().unwrap();
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .locality = ModelLocality::OnDevice;
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .tier = ModelTierRef("resident-local".into());
    vault.set_purpose_default_table(&table).unwrap();
    assert!(vault.model_manifest().unwrap().is_none());
    let mut request = LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    bind(
        &vault,
        super::super::manifest::ModelRole::GenerativeReasoner,
        &mut request,
        None,
    )
    .unwrap();
    assert_eq!(request.model, model);
    assert_eq!(request.envelope.locality, ModelLocality::OnDevice);
    assert_eq!(request.envelope.tier.resolved().as_str(), "resident-local");
}

#[test]
fn resident_local_default_cannot_relabel_remote_model_to_bypass_budget() {
    use super::super::{BudgetExhaustionPolicy, BudgetGuard, LlmRequest, ModelId};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let mut table = vault.purpose_default_table().unwrap();
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .locality = ModelLocality::OnDevice;
    vault.set_purpose_default_table(&table).unwrap();
    let mut request = LlmRequest {
        model: ModelId::new("remote/consolidation@r1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: super::super::CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    let original = request.clone();
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::GenerativeReasoner,
            &mut request,
            None
        ),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(request, original);
    let guard =
        BudgetGuard::with_reserve_units("spent", 0, 1, BudgetExhaustionPolicy::ContinueOnLocal);
    assert!(guard.admit_for_request(&request).is_err());
    request.envelope.locality = ModelLocality::OnDevice;
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::GenerativeReasoner,
            &mut request,
            None
        ),
        Err(Error::InvalidConfig(_))
    ));
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::OpenaiCompat,
            catalog: LlmCatalogEntry {
                model: request.model.clone(),
                display_name: "remote".into(),
                locality: ModelLocality::ThirdParty,
                context_window_tokens: 4096,
                max_output_tokens: None,
                cost: Some(LlmCatalogCost {
                    input_per_million: "1".into(),
                    output_per_million: "1".into(),
                    cache_read_per_million: None,
                    cache_write_per_million: None,
                }),
                capabilities: vec![],
                metadata: Default::default(),
            },
            scores: Default::default(),
            fetched_at: Default::default(),
        })
        .unwrap();
    assert!(matches!(
        bind(
            &vault,
            super::super::manifest::ModelRole::GenerativeReasoner,
            &mut request,
            None
        ),
        Err(Error::InvalidConfig(_))
    ));
}
