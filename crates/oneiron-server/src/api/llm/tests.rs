use super::*;
use oneiron::*;
use oneiron_remote::llm::{OwnServerTransport, RemoteLlmClient};
use std::collections::BTreeMap;

struct Backend;
fn backend_error(model: &ModelId) -> Option<FatalLlmError> {
    match model.name() {
        "fail" => Some(FatalLlmError::Auth),
        "filtered" => Some(FatalLlmError::ContentFiltered),
        "empty" => Some(FatalLlmError::EmptyResponse),
        "unsupported" => Some(FatalLlmError::Unsupported(
            oneiron::llm::UnsupportedCapability {
                capability: LlmCapability::JsonResponse,
                model: Some(model.clone()),
                reason: Some("fixture capability".into()),
            },
        )),
        _ => None,
    }
}
fn response() -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "answer".into(),
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 2,
                ..Default::default()
            },
            output: LlmOutputUsage {
                total: 3,
                text: 3,
                reasoning: 0,
            },
            raw_provider: serde_json::json!({}),
        },
        finish_reason: FinishReason::Stop,
    }
}
// One request per call: the raw routes' gate wraps it. A stream this
// fixture refuses to start is refused here, before the gate dispatches it.
impl oneiron::llm::SingleRouteBackend for Backend {
    fn preflight(&self, request: &LlmRequest, stream: bool) -> oneiron::LlmResult<()> {
        match backend_error(&request.model) {
            Some(error) if stream => Err(error.into()),
            _ => Ok(()),
        }
    }
}
impl LlmBackend for Backend {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            if let Some(error) = backend_error(&request.model) {
                Err(error.into())
            } else {
                Ok(response())
            }
        })
    }
    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        if let Some(error) = backend_error(&request.model) {
            return Err(error.into());
        }
        let response = response();
        Ok(LlmStream::new(futures_util::stream::iter(vec![
            Ok(LlmStreamEvent::TextStart {
                part_id: "t".into(),
            }),
            Ok(LlmStreamEvent::TextDelta {
                part_id: "t".into(),
                text: "answer".into(),
            }),
            Ok(LlmStreamEvent::TextEnd {
                part_id: "t".into(),
            }),
            Ok(LlmStreamEvent::Done {
                message: response.message,
                usage: response.usage,
                finish_reason: response.finish_reason,
            }),
        ])))
    }
}
fn request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("own/model@1").unwrap(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}
fn seed_models(vault: &Vault) {
    for name in ["model", "fail", "filtered", "empty", "unsupported"] {
        vault
            .put_model_registry_row(&oneiron::llm::registry::ModelRegistryRow {
                version: 1,
                wire: oneiron::llm::registry::ModelWireFormat::OpenaiCompat,
                catalog: LlmCatalogEntry {
                    model: ModelId::new(format!("own/{name}@1")).unwrap(),
                    display_name: name.into(),
                    locality: ModelLocality::ThirdParty,
                    context_window_tokens: 4096,
                    max_output_tokens: Some(100),
                    cost: Some(oneiron::llm::LlmCatalogCost {
                        input_per_million: "1".into(),
                        output_per_million: "1".into(),
                        cache_read_per_million: None,
                        cache_write_per_million: None,
                    }),
                    capabilities: vec![LlmCapability::Streaming],
                    metadata: BTreeMap::new(),
                },
                scores: BTreeMap::new(),
                fetched_at: BTreeMap::new(),
            })
            .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_remote_transport_refuses_issuer_secret_without_a_holder_proof() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    seed_models(&vault);
    let budget = BudgetGuard::with_reserve_units("host", 100, 10, BudgetExhaustionPolicy::Suspend);
    let server = SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("fixture-owner".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_llm_backend(Arc::new(Backend), budget.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        axum::serve(listener, crate::api::api_routes(Arc::new(server)))
            .await
            .unwrap();
    });
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let guard =
            BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
        let lease = guard.admit_for_request(&request()).unwrap().lease;
        for raw in ["fixture-owner", "wrong", "v2.scope=core:write.invalid"] {
            let client = RemoteLlmClient::connect(&origin, raw).unwrap();
            assert!(matches!(
                runtime.block_on(client.generate(request(), &lease)),
                Err(LlmError::Fatal(FatalLlmError::Auth))
            ));
        }
        guard.abort(&lease).unwrap();
    })
    .await
    .unwrap();
    assert_eq!(budget.read().used_units, 0);
    assert_eq!(budget.read().reserved_units, 0);
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_top_scope_credential_carries_llm_results_and_host_usage() {
    use oneiron::authority::{HostSlipIssuer, PairingPrincipal, format_pairing_link};
    use oneiron::federation::Scope;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    seed_models(&vault);
    let person = vault.ensure_embedded_owner_actor().unwrap().to_hex();
    let budget = BudgetGuard::with_reserve_units("host", 100, 10, BudgetExhaustionPolicy::Suspend);
    let server = SyncServer::new(
        vault.clone(),
        crate::config::SyncServerConfig {
            auth_secret: Some("fixture-owner".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_llm_backend(Arc::new(Backend), budget.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        axum::serve(listener, crate::api::api_routes(Arc::new(server)))
            .await
            .unwrap();
    });
    // Scope::top() for a PERSON is owner-grade: the LLM route's floor.
    let issuer = HostSlipIssuer::from_secret(b"fixture-owner").unwrap();
    let link = vault
        .issue_pairing_link_for_principal(
            &issuer,
            Scope::top(),
            3600,
            PairingPrincipal {
                holder_ref: Some(person.clone()),
                actor_class: Some("human".into()),
                org_ref: None,
                write_facet: None,
            },
        )
        .unwrap();
    let link = format_pairing_link(&origin, &link.code, &person);
    let runtime = tokio::runtime::Handle::current();
    let host_budget = budget.clone();
    tokio::task::spawn_blocking(move || {
        // Pair through the public SDK adapter; do not use the issuer secret as
        // the LLM client's credential.
        let (origin, credential) = oneiron_remote::OneironClient::pair(&link).unwrap();
        let client = RemoteLlmClient::connect(&origin, &credential).unwrap();
        let guard =
            BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
        let lease = guard.admit_for_request(&request()).unwrap().lease;

        let generated = runtime
            .block_on(client.generate(request(), &lease))
            .unwrap();
        assert_eq!(generated, response());
        assert_eq!(host_budget.read().used_units, 5);
        assert_eq!(host_budget.read().reserved_units, 0);

        let mut stream = client.stream(request(), &lease).unwrap();
        let mut events = Vec::new();
        while let Some(event) = runtime.block_on(stream.next()) {
            events.push(event.unwrap());
        }
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events.last(),
            Some(LlmStreamEvent::Done { usage, .. }) if usage == &response().usage
        ));
        assert_eq!(host_budget.read().used_units, 10);
        assert_eq!(host_budget.read().reserved_units, 0);

        for (index, name) in ["fail", "filtered", "empty", "unsupported"]
            .into_iter()
            .enumerate()
        {
            let mut bad = request();
            bad.model = ModelId::new(format!("own/{name}@1")).unwrap();
            let expected = backend_error(&bad.model).unwrap();
            assert_eq!(
                runtime.block_on(client.generate(bad, &lease)),
                Err(expected.into())
            );
            assert_eq!(host_budget.read().used_units, 20 + 10 * index as u64);
            assert_eq!(host_budget.read().reserved_units, 0);
        }

        let mut bad = request();
        bad.model = ModelId::new("own/fail@1").unwrap();
        let mut failed = client.stream(bad, &lease).unwrap();
        assert_eq!(
            runtime.block_on(failed.next()),
            Some(Err(LlmError::Fatal(FatalLlmError::Auth)))
        );
        guard.abort(&lease).unwrap();
    })
    .await
    .unwrap();
    // A stream its backend refuses to start (in its preflight, before the
    // run's gate dispatches it) never starts provider work, so the server
    // releases its reservation rather than charging the host.
    for _ in 0..100 {
        if budget.read().reserved_units == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.read().used_units, 50);
    assert_eq!(budget.read().reserved_units, 0);
    serving.abort();
}

#[tokio::test]
async fn unconfigured_and_exhausted_llm_routes_fail_closed() {
    use tower::ServiceExt;
    for configured in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        seed_models(&vault);
        let mut server = SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("owner".into()),
                ..Default::default()
            },
        )
        .unwrap();
        if configured {
            server = server.with_llm_backend(
                Arc::new(Backend),
                BudgetGuard::with_reserve_units(
                    "empty",
                    0,
                    10,
                    BudgetExhaustionPolicy::ContinueOnLocal,
                ),
            );
        }
        let server = Arc::new(server);
        let router = crate::api::api_routes(server.clone());
        let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-budget");
        for verb in ["generate", "stream"] {
            let mut wire = request();
            wire.envelope.locality = ModelLocality::OnDevice;
            let response = router
                .clone()
                .oneshot(crate::test_credentials::bind_slip_request(
                    &server,
                    &slip,
                    &key,
                    axum::http::Request::post(format!("/v1/llm/{verb}"))
                        .header("content-type", "application/json")
                        .header("x-oneiron-budget-lease", "forged-remote-lease")
                        .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if configured {
                    StatusCode::PAYMENT_REQUIRED
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            );
        }
    }
}

#[tokio::test]
async fn cancelled_and_failed_streams_charge_reserved_estimate_without_terminal_usage() {
    use tower::ServiceExt;
    struct Partial(bool);
    // One request per call: the raw routes' gate wraps it.
    impl oneiron::llm::SingleRouteBackend for Partial {
        fn preflight(&self, _: &LlmRequest, _: bool) -> oneiron::LlmResult<()> {
            Ok(())
        }
    }
    impl LlmBackend for Partial {
        fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
            unreachable!()
        }
        fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
            let delta = futures_util::stream::iter(vec![Ok(LlmStreamEvent::TextDelta {
                part_id: "t".into(),
                text: "spent".into(),
            })]);
            if self.0 {
                Ok(LlmStream::new(delta.chain(futures_util::stream::once(
                    async { Err(RetryableLlmError::StreamCut.into()) },
                ))))
            } else {
                Ok(LlmStream::new(delta.chain(futures_util::stream::pending())))
            }
        }
    }
    for fail in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        seed_models(&vault);
        let budget =
            BudgetGuard::with_reserve_units("partial", 100, 10, BudgetExhaustionPolicy::Suspend);
        let server = SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("owner".into()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_llm_backend(Arc::new(Partial(fail)), budget.clone());
        let server = Arc::new(server);
        let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-stream");
        let response = crate::api::api_routes(server.clone())
            .oneshot(crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &key,
                axum::http::Request::post("/v1/llm/stream")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        let mut body = response.into_body().into_data_stream();
        let first = body.next().await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_slice::<LlmStreamEvent>(&first).unwrap(),
            LlmStreamEvent::TextDelta { .. }
        ));
        if fail {
            let error = body.next().await.unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&error).unwrap();
            assert!(value.pointer("/error/llm").is_some());
            assert!(body.next().await.is_none());
        }
        drop(body);
        // Task cancellation is cooperative; yield without timers until the lease closes.
        for _ in 0..100 {
            if budget.read().reserved_units == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.read().reserved_units, 0);
        assert_eq!(budget.read().used_units, 10);
    }
}

#[tokio::test]
async fn successful_calls_without_usage_charge_estimates_for_both_verbs() {
    use tower::ServiceExt;
    struct MissingUsage;
    // One request per call: the raw routes' gate wraps it.
    impl oneiron::llm::SingleRouteBackend for MissingUsage {
        fn preflight(&self, _: &LlmRequest, _: bool) -> oneiron::LlmResult<()> {
            Ok(())
        }
    }
    impl LlmBackend for MissingUsage {
        fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
            Box::pin(async {
                let mut answer = response();
                answer.usage = LlmUsage::zero();
                Ok(answer)
            })
        }
        fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
            let answer = response();
            Ok(LlmStream::new(futures_util::stream::iter(vec![Ok(
                LlmStreamEvent::Done {
                    message: answer.message,
                    usage: LlmUsage::zero(),
                    finish_reason: answer.finish_reason,
                },
            )])))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    seed_models(&vault);
    let budget =
        BudgetGuard::with_reserve_units("missing-usage", 20, 10, BudgetExhaustionPolicy::Suspend);
    let server = SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_llm_backend(Arc::new(MissingUsage), budget.clone());
    let server = Arc::new(server);
    let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-missing-usage");
    let router = crate::api::api_routes(server.clone());
    for (index, verb) in ["generate", "stream", "generate"].into_iter().enumerate() {
        let reply = router
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &key,
                axum::http::Request::post(format!("/v1/llm/{verb}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        if index == 2 {
            assert_eq!(reply.status(), StatusCode::PAYMENT_REQUIRED);
        } else {
            assert_eq!(reply.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(reply.into_body(), 65_536)
                .await
                .unwrap();
            if verb == "generate" {
                let terminal: LlmResponse = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(terminal.message, response().message);
            } else {
                assert!(matches!(
                    serde_json::from_slice::<LlmStreamEvent>(&bytes).unwrap(),
                    LlmStreamEvent::Done { .. }
                ));
            }
        }
        assert_eq!(budget.read().used_units, 10 * ((index + 1).min(2) as u64));
        assert_eq!(budget.read().reserved_units, 0);
    }
}

type Pick = fn(&mut LlmRequest);

#[tokio::test]
async fn a_raw_call_that_picks_its_own_model_or_route_is_refused_with_the_key() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    // A backend that answers anything, as a provider key would, and counts
    // what reached it.
    struct Counting(AtomicUsize);
    // One request per call: the raw routes' gate wraps it.
    impl oneiron::llm::SingleRouteBackend for Counting {
        fn preflight(&self, _: &LlmRequest, _: bool) -> oneiron::LlmResult<()> {
            Ok(())
        }
    }
    impl LlmBackend for Counting {
        fn generate<'a>(&'a self, r: LlmRequest, l: &'a BudgetLease) -> LlmGenerateFuture<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Backend.generate(r, l)
        }
        fn stream<'a>(&'a self, r: LlmRequest, l: &'a BudgetLease) -> LlmStreamResult<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Backend.stream(r, l)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    seed_models(&vault);
    let budget = BudgetGuard::with_reserve_units("raw", 100, 10, BudgetExhaustionPolicy::Suspend);
    let backend = Arc::new(Counting(AtomicUsize::new(0)));
    let receipts = Arc::new(oneiron::llm::run_admission::MemoryReceipts::default());
    let server = SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_llm_backend(backend.clone(), budget.clone())
    .with_run_receipts(receipts.clone());
    let server = Arc::new(server);
    let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-route-selector");
    let router = crate::api::api_routes(server.clone());
    let picks: [(&str, Pick); 3] = [
        ("model", |r| {
            r.params.insert("model".into(), "other/model@1".into());
        }),
        ("openai.models", |r| {
            r.provider_options.insert(
                "openai".into(),
                serde_json::json!({ "models": ["other/model@1"] }),
            );
        }),
        ("provider", |r| {
            r.provider_options
                .insert("provider".into(), serde_json::json!({ "order": ["other"] }));
        }),
    ];
    for verb in ["generate", "stream"] {
        for (named, pick) in picks {
            let mut wire = request();
            pick(&mut wire);
            let reply = router
                .clone()
                .oneshot(crate::test_credentials::bind_slip_request(
                    &server,
                    &slip,
                    &key,
                    axum::http::Request::post(format!("/v1/llm/{verb}"))
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{verb} {named}");
            let bytes = axum::body::to_bytes(reply.into_body(), 65_536)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body,
                serde_json::json!({"error":{"code":"route_selector_forbidden","key":named}}),
                "{verb} {named}"
            );
        }
    }
    assert_eq!(
        backend.0.load(Ordering::SeqCst),
        0,
        "a call reached the backend"
    );
    assert_eq!(budget.read().used_units, 0);
    assert_eq!(budget.read().reserved_units, 0);
    // Each refusal is receipted on the raw run: one denial naming the key,
    // with no lease.
    let denied: Vec<String> = receipts
        .rows()
        .into_iter()
        .map(|row| match row.event {
            oneiron::llm::run_admission::RunEvent::Denied {
                reason: oneiron::llm::run_admission::RunDenied::RouteOverride { key },
                lease: None,
                ..
            } => key,
            other => panic!("not a route denial: {other:?}"),
        })
        .collect();
    assert_eq!(denied, ["model", "openai.models", "provider"].repeat(2));
}

/// The same refusal on a server with no model backend: the 400 and its one
/// `Denied` row, with nothing reserved (Astra on #1382). A provider-option
/// namespace no adapter reads is caller text: neither the reply nor the row
/// (which the default sink logs as it is) quotes it.
#[tokio::test]
async fn a_raw_call_that_picks_its_own_route_has_its_row_with_no_backend_attached() {
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let receipts = Arc::new(oneiron::llm::run_admission::MemoryReceipts::default());
    let server = SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_run_receipts(receipts.clone());
    let server = Arc::new(server);
    let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-route-no-backend");
    let router = crate::api::api_routes(server.clone());
    let picks: [(&str, Pick); 2] = [
        ("model", |r| {
            r.params.insert("model".into(), "other/model@1".into());
        }),
        ("*.model", |r| {
            r.provider_options.insert(
                "Bearer sk-test-sentinel-0000".into(),
                serde_json::json!({ "model": "other/model@1" }),
            );
        }),
    ];
    for verb in ["generate", "stream"] {
        for (named, pick) in picks {
            let mut wire = request();
            pick(&mut wire);
            let reply = router
                .clone()
                .oneshot(crate::test_credentials::bind_slip_request(
                    &server,
                    &slip,
                    &key,
                    axum::http::Request::post(format!("/v1/llm/{verb}"))
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{verb} {named}");
            let bytes = axum::body::to_bytes(reply.into_body(), 65_536)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body,
                serde_json::json!({"error":{"code":"route_selector_forbidden","key":named}}),
                "{verb} {named}"
            );
        }
    }
    let rows = receipts.rows();
    for row in &rows {
        let logged = serde_json::to_string(row).unwrap();
        assert!(!logged.contains("sk-test-sentinel"), "{logged}");
    }
    let denied: Vec<String> = rows
        .into_iter()
        .map(|row| match row.event {
            oneiron::llm::run_admission::RunEvent::Denied {
                reason: oneiron::llm::run_admission::RunDenied::RouteOverride { key },
                lease: None,
                ..
            } => key,
            other => panic!("not a route denial: {other:?}"),
        })
        .collect();
    assert_eq!(denied, ["model", "*.model", "model", "*.model"]);
}

/// Review repro (Astra R4 P1): the world a raw caller names does not vouch
/// for the text it sends. A raw call to a `[models]` seat that names a
/// portable world is held on the device while any world stays on it, on both
/// routes: the typed `kept_on_device` outcome with its receipt, and the cloud
/// offer never sees the text.
#[tokio::test]
async fn a_raw_call_naming_a_portable_world_stays_while_a_world_does() {
    use crate::ai_host::AiHost;
    use crate::ai_host::test_support::{TEST_SECRET, models_toml, rooted_vault};
    use crate::fake_llm::{FakeLlm, Reply};
    use oneiron::llm::run_admission::{MemoryReceipts, RunDenied, RunEvent};
    use tower::ServiceExt;
    let device = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let cloud = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let config = models_toml(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
[dreamer]
enabled = false
"#,
        device.base_url, cloud.base_url
    ));
    let (_dir, vault) = rooted_vault();
    let host = AiHost::start(Arc::clone(&vault), Some(&config), true).await;
    let receipts = Arc::new(MemoryReceipts::default());
    let config = crate::config::SyncServerConfig {
        auth_secret: Some(TEST_SECRET.into()),
        ..Default::default()
    };
    let server = SyncServer::new(Arc::clone(&vault), config)
        .unwrap()
        .with_ai(host.handle())
        .with_run_receipts(receipts.clone());
    let server = Arc::new(server);
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(TEST_SECRET.as_bytes()).unwrap();
    let world = |kept: bool| {
        let world = EntityId::now();
        let when = TimeRange { start: 1, end: 1 };
        let kind = oneiron::registry::ENTITY_TYPE_WORLD;
        vault.put_entity(&world, kind, when, 1, b"world").unwrap();
        if kept {
            vault
                .keep_world_on_this_machine_under_for_test(&issuer, world, true)
                .unwrap();
        }
        world
    };
    world(true);
    let handle = host.handle();
    let seat = handle
        .seat(oneiron::llm::manifest::ModelRole::Checker)
        .expect("seat");
    let mut wire = request();
    wire.model = seat.model.clone();
    wire.envelope.locality = seat.locality;
    wire.envelope.scope.world = Some(world(false));
    wire.messages = vec![LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: "about the world".into(),
        }],
    }];
    let (slip, key) = crate::test_credentials::credential(&server, "jti=llm-raw-world");
    let router = crate::api::api_routes(server.clone());
    let kept: LlmError = RetryableLlmError::KeptOnDevice {
        retry_after: None,
        resets_at: Vec::new(),
    }
    .into();
    for verb in ["generate", "stream"] {
        let reply = router
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &key,
                axum::http::Request::post(format!("/v1/llm/{verb}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        let status = reply.status();
        let bytes = axum::body::to_bytes(reply.into_body(), 65_536)
            .await
            .unwrap();
        // A refused call answers whole; a stream may carry its error as its
        // first line. Either names the same outcome.
        let line = bytes.split(|byte| *byte == b'\n').next().unwrap();
        let body: serde_json::Value = serde_json::from_slice(line).unwrap();
        let error = serde_json::from_value::<LlmError>(body["error"]["llm"].clone()).ok();
        assert_eq!(error.as_ref(), Some(&kept), "{verb}: {body}");
        if verb == "generate" {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            assert_eq!(body["error"]["code"], "kept_on_device");
        }
    }
    assert!(
        !device.seen().is_empty(),
        "the calls were tried on the device"
    );
    assert!(cloud.seen().is_empty(), "the text stayed here");
    let held = receipts
        .rows()
        .into_iter()
        .filter(|row| {
            matches!(
                row.event,
                RunEvent::Denied {
                    reason: RunDenied::KeptOnDevice,
                    ..
                }
            )
        })
        .count();
    assert_eq!(held, 2, "each held call is receipted once");
    host.shutdown().await;
}
