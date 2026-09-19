use super::*;
use oneiron::*;
use oneiron_remote::llm::{OwnServerTransport, RemoteLlmClient};
use std::collections::BTreeMap;

struct Backend;
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
            if request.model.name() == "fail" {
                Err(FatalLlmError::Auth.into())
            } else {
                Ok(response())
            }
        })
    }
    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        if request.model.name() == "fail" {
            return Err(FatalLlmError::Auth.into());
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_server_transport_reaches_authenticated_server_and_settles_local_budget() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
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
        let denied = RemoteLlmClient::connect(&origin, "wrong").unwrap();
        assert!(matches!(runtime.block_on(denied.generate(request(), &lease)), Err(LlmError::Fatal(FatalLlmError::Auth))));
        let scoped_token = crate::auth::mint_core_token_v2("fixture-owner", "scope=core:write");
        let scoped = RemoteLlmClient::connect(&origin, &scoped_token).unwrap();
        assert!(matches!(runtime.block_on(scoped.generate(request(), &lease)), Err(LlmError::Fatal(FatalLlmError::Auth))));
        guard.abort(&lease).unwrap();
    }).await.unwrap();
    assert_eq!(budget.read().used_units, 10);
    assert_eq!(budget.read().reserved_units, 0);
    serving.abort();
}

#[tokio::test]
async fn unconfigured_and_exhausted_llm_routes_fail_closed() {
    use tower::ServiceExt;
    for configured in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
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
                BudgetGuard::with_reserve_units("empty", 0, 10, BudgetExhaustionPolicy::Suspend),
            );
        }
        let router = crate::api::api_routes(Arc::new(server));
        for verb in ["generate", "stream"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::post(format!("/v1/llm/{verb}"))
                        .header("authorization", "Bearer owner")
                        .header("content-type", "application/json")
                        .header("x-oneiron-budget-lease", "forged-remote-lease")
                        .body(Body::from(serde_json::to_vec(&request()).unwrap()))
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
