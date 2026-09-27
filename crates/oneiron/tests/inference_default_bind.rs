//! Public no-manifest local binding must use one registry snapshot, not a nested reader.
use oneiron::llm::{
    LlmCatalogCost, LlmCatalogEntry,
    manifest::ModelRole,
    registry::{ModelRegistryRow, ModelWireFormat},
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, Error, LlmRequest, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence, Vault, VaultConfig,
};

fn request(model: ModelId, locality: ModelLocality) -> LlmRequest {
    LlmRequest {
        model,
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    }
}

fn bind(vault: &Vault, role: ModelRole, request: &mut LlmRequest) -> Result<(), Error> {
    let host = oneiron::llm::HostInferenceContext {
        binding: oneiron::llm::HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality: request.envelope.locality,
        },
        extraction_egress: None,
    };
    let authorized = vault.authorize_model_role(role, request.clone(), &host)?;
    *request = authorized.into_request();
    Ok(())
}

#[test]
fn registered_local_model_uses_the_stored_default_without_nested_lmdb_reader() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let model = ModelId::new("local/consolidation@r1").expect("model id");
    let local_row = ModelRegistryRow {
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
    };
    vault
        .put_model_registry_row(&local_row)
        .expect("register local model");
    let mut table = vault.purpose_default_table().expect("read defaults");
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .expect("built-in row")
        .locality = ModelLocality::OnDevice;
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .expect("built-in row")
        .tier = ModelTierRef("resident-local".into());
    vault
        .set_purpose_default_table(&table)
        .expect("store defaults");
    assert!(vault.model_manifest().expect("read manifest").is_none());

    let mut call = request(model.clone(), ModelLocality::OnDevice);
    bind(&vault, ModelRole::GenerativeReasoner, &mut call)
        .expect("local binding must not open another reader");
    assert_eq!(call.model, model);
    assert_eq!(call.envelope.locality, ModelLocality::OnDevice);
    assert_eq!(call.envelope.tier.resolved().as_str(), "resident-local");

    // An already-selected remote route is never relabeled into an unmetered local lease.
    let mut remote = request(
        ModelId::new("remote/consolidation@r1").expect("remote model"),
        ModelLocality::OwnServer,
    );
    let before = remote.clone();
    assert!(matches!(
        bind(&vault, ModelRole::GenerativeReasoner, &mut remote),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(remote, before);

    // A local catalog label is not sufficient when the registered transport is remote.
    let mut wrong_wire = local_row;
    wrong_wire.catalog.model = ModelId::new("remote/mislabeled@r1").expect("model id");
    wrong_wire.wire = ModelWireFormat::OpenaiCompat;
    vault
        .put_model_registry_row(&wrong_wire)
        .expect("register mislabeled model");
    let mut mislabeled = request(wrong_wire.catalog.model, ModelLocality::OnDevice);
    let before = mislabeled.clone();
    assert!(matches!(
        bind(&vault, ModelRole::GenerativeReasoner, &mut mislabeled),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(mislabeled, before);
}

#[test]
fn storing_the_shipped_rows_does_not_change_a_host_bound_decision() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let model = ModelId::new("own/answer@r1").expect("model id");
    let mut input = request(model.clone(), ModelLocality::OwnServer);
    input.envelope.purpose = CallPurpose::AnswerGen;
    input.envelope.tier.per_seat = Some(ModelTierRef("explicit-host".into()));
    let host = oneiron::llm::HostInferenceContext {
        binding: oneiron::llm::HostInferenceBinding::Advertised {
            model,
            locality: ModelLocality::OwnServer,
        },
        extraction_egress: None,
    };
    let absent = vault
        .authorize_model_role(ModelRole::GenerativeReasoner, input.clone(), &host)
        .expect("explicit host route without stored table");
    vault
        .set_purpose_default_table(&vault.purpose_default_table().expect("defaults"))
        .expect("store the unchanged shipped policy");
    let stored = vault
        .authorize_model_role(ModelRole::GenerativeReasoner, input, &host)
        .expect("same explicit host route after storing policy");
    assert_eq!(absent.request(), stored.request());
    assert_eq!(absent.binding(), stored.binding());
}
