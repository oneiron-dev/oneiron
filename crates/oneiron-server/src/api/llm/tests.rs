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
async fn own_server_transport_reaches_authenticated_server_and_settles_local_budget() {
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
        let client = RemoteLlmClient::connect(&origin, "fixture-owner").unwrap();
        let guard = BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
        let lease = guard.admit_for_request(&request()).unwrap().lease;
        assert_eq!(runtime.block_on(client.generate(request(), &lease)).unwrap(), response());
        let mut stream = client.stream(request(), &lease).unwrap();
        let mut events = Vec::new();
        while let Some(event) = runtime.block_on(stream.next()) { events.push(event.unwrap()); }
        assert_eq!(events.len(), 4);
        assert!(matches!(events.last(), Some(LlmStreamEvent::Done { usage, .. }) if usage == &response().usage));
        let mut bad = request(); bad.model = ModelId::new("own/fail@1").unwrap();
        assert!(matches!(runtime.block_on(client.generate(bad.clone(), &lease)), Err(LlmError::Fatal(FatalLlmError::Auth))));
        let mut failed = client.stream(bad, &lease).unwrap();
        assert!(matches!(runtime.block_on(failed.next()), Some(Err(LlmError::Fatal(FatalLlmError::Auth)))));
        for name in ["filtered", "empty", "unsupported"] {
            let mut typed = request();
            typed.model = ModelId::new(format!("own/{name}@1")).unwrap();
            let expected = backend_error(&typed.model).unwrap();
            assert_eq!(runtime.block_on(client.generate(typed, &lease)), Err(expected.into()));
        }
        let denied = RemoteLlmClient::connect(&origin, "wrong").unwrap();
        assert!(matches!(runtime.block_on(denied.generate(request(), &lease)), Err(LlmError::Fatal(FatalLlmError::Auth))));
        let scoped_token = crate::auth::mint_core_token_v2("fixture-owner", "scope=core:write");
        let scoped = RemoteLlmClient::connect(&origin, &scoped_token).unwrap();
        assert!(matches!(runtime.block_on(scoped.generate(request(), &lease)), Err(LlmError::Fatal(FatalLlmError::Auth))));
        guard.abort(&lease).unwrap();
    }).await.unwrap();
    assert_eq!(budget.read().used_units, 50);
    assert_eq!(budget.read().reserved_units, 0);
    serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_credential_streams_through_the_llm_route() {
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
    .with_llm_backend(Arc::new(Backend), budget);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
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
            },
        )
        .unwrap();
    let link = format_pairing_link(&origin, &link.code, &person);
    let runtime = tokio::runtime::Handle::current();
    let events = tokio::task::spawn_blocking(move || {
        let (origin, credential) = oneiron_remote::OneironClient::pair(&link).unwrap();
        let client = RemoteLlmClient::connect(&origin, &credential).unwrap();
        let guard =
            BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
        let lease = guard.admit_for_request(&request()).unwrap().lease;
        let mut stream = client.stream(request(), &lease).unwrap();
        let mut events = Vec::new();
        while let Some(event) = runtime.block_on(stream.next()) {
            events.push(event.unwrap());
        }
        events.len()
    })
    .await
    .unwrap();
    assert_eq!(events, 4);
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
        let router = crate::api::api_routes(Arc::new(server));
        for verb in ["generate", "stream"] {
            let mut wire = request();
            wire.envelope.locality = ModelLocality::OnDevice;
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::post(format!("/v1/llm/{verb}"))
                        .header("authorization", "Bearer owner")
                        .header("content-type", "application/json")
                        .header("x-oneiron-budget-lease", "forged-remote-lease")
                        .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                        .unwrap(),
                )
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
        let response = crate::api::api_routes(Arc::new(server))
            .oneshot(
                axum::http::Request::post("/v1/llm/stream")
                    .header("authorization", "Bearer owner")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            )
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
    let router = crate::api::api_routes(Arc::new(server));
    for (index, verb) in ["generate", "stream", "generate"].into_iter().enumerate() {
        let reply = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/v1/llm/{verb}"))
                    .header("authorization", "Bearer owner")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            )
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
