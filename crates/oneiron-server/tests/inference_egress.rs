//! Extraction default changes require a host gate at storage and dispatch.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use oneiron::llm::{
    LlmCatalogCost, LlmCatalogEntry, PurposeDefaultTable,
    registry::{ModelRegistryRow, ModelWireFormat},
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    LlmBackend, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

struct Backend(Arc<AtomicUsize>);
impl LlmBackend for Backend {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(oneiron::FatalLlmError::InvalidRequest.into()) })
    }
    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
fn server(
    vault: Arc<Vault>,
    count: Arc<AtomicUsize>,
    predicate: Option<Arc<dyn oneiron::llm::ExtractionEgressPredicate>>,
) -> axum::Router {
    let mut server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .expect("server")
    .with_llm_backend(
        Arc::new(Backend(count)),
        BudgetGuard::with_reserve_units("extraction", 100, 10, BudgetExhaustionPolicy::Suspend),
    );
    if let Some(predicate) = predicate {
        server = server.with_extraction_egress(predicate);
    }
    build_app(Arc::new(server))
}
fn put(table: &PurposeDefaultTable) -> Request<Body> {
    Request::put("/v1/llm/defaults")
        .header("authorization", "Bearer owner")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(table).expect("encode table")))
        .expect("put request")
}
fn call(model: &ModelId) -> Request<Body> {
    let request = LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    Request::post("/v1/llm/generate")
        .header("authorization", "Bearer owner")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&request).expect("encode request"),
        ))
        .expect("post request")
}
#[tokio::test]
async fn owner_edits_nonlocal_default_only_with_host_egress_and_call_rechecks() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let model = ModelId::new("own/extraction@r1").expect("model");
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::OwnServer,
            catalog: LlmCatalogEntry {
                model: model.clone(),
                display_name: "own extraction".into(),
                locality: ModelLocality::OwnServer,
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
        .expect("registry");
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = vault.purpose_default_table().expect("table");
    table.extraction_max_locality = ModelLocality::OwnServer;
    table
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("row")
        .locality = ModelLocality::OwnServer;
    assert_eq!(
        server(vault.clone(), count.clone(), None)
            .oneshot(put(&table))
            .await
            .expect("response")
            .status(),
        StatusCode::BAD_REQUEST
    );
    let policy_reader = vault.clone();
    let allow: Arc<dyn oneiron::llm::ExtractionEgressPredicate> =
        Arc::new(move |request: &LlmRequest| {
            policy_reader.purpose_default_table().is_ok()
                && request.model.as_str() == "own/extraction@r1"
                && request.envelope.locality == ModelLocality::OwnServer
        });
    let allowed = server(vault.clone(), count.clone(), Some(allow));
    assert_eq!(
        allowed
            .clone()
            .oneshot(put(&table))
            .await
            .expect("response")
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        vault.purpose_default_table().expect("stored").purposes[&CallPurpose::Extraction].locality,
        ModelLocality::OwnServer
    );
    assert_eq!(
        allowed
            .oneshot(call(&model))
            .await
            .expect("response")
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(count.load(Ordering::SeqCst), 1, "allowed backend reached");
    assert_eq!(
        server(vault.clone(), count.clone(), None)
            .oneshot(call(&model))
            .await
            .expect("response")
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut stream = call(&model);
    *stream.uri_mut() = "/v1/llm/stream".parse().expect("stream path");
    assert_eq!(
        server(vault.clone(), count.clone(), None)
            .oneshot(stream)
            .await
            .expect("stream refusal")
            .status(),
        StatusCode::FORBIDDEN,
    );
    let deny: Arc<dyn oneiron::llm::ExtractionEgressPredicate> = Arc::new(|_: &LlmRequest| false);
    assert_eq!(
        server(vault, count.clone(), Some(deny))
            .oneshot(call(&model))
            .await
            .expect("response")
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "denials never reached backend"
    );
}
