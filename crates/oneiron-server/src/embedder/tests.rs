//! Provider-slot rows: the numerics contract, and the endpoint provider driven
//! against a real HTTP server.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use serde_json::{Value, json};

use super::endpoint::{ProbeError, ProbeOutcome};
use super::*;
use crate::config::{EmbedderConfig, EmbedderProvider, EndpointEmbedderConfig};

const DIMS: usize = 8;

fn common() -> EmbedderCommon {
    EmbedderCommon {
        model_id: "test/model@rev".to_owned(),
        dimensions: DIMS,
        query_instruction: "Instruct: answer\nQuery: ".to_owned(),
    }
}

// ─── numerics ────────────────────────────────────────────────────────────

#[test]
fn a_vector_of_the_wrong_width_is_refused() {
    let error = common()
        .finish_vector(vec![1.0; DIMS + 1])
        .expect_err("a wrong width is refused");
    assert!(matches!(
        error,
        oneiron::Error::DimensionMismatch {
            expected: DIMS,
            got: 9
        }
    ));
}

#[test]
fn a_non_finite_component_is_refused_with_its_index() {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut vector = vec![1.0; DIMS];
        vector[3] = bad;
        let error = common()
            .finish_vector(vector)
            .expect_err("a non-finite component is refused");
        assert!(
            matches!(error, oneiron::Error::InvalidVector { index: 3, .. }),
            "{error:?}"
        );
    }
}

#[test]
fn a_zero_vector_is_refused_rather_than_normalised() {
    let error = common()
        .finish_vector(vec![0.0; DIMS])
        .expect_err("a zero vector has no direction");
    assert!(matches!(error, oneiron::Error::InvalidVector { .. }));
}

#[test]
fn the_finished_vector_is_unit_norm() {
    let raw: Vec<f32> = (1..=DIMS).map(|n| n as f32).collect();
    let finished = common().finish_vector(raw).expect("finished");
    let norm = finished.iter().map(|v| v * v).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-3, "norm was {norm}");
}

/// The live probe that motivated the guard returned a component of `-5.8e-38`,
/// below the smallest f16 subnormal. Every component the guard emits must be a
/// value `half::f16` holds exactly and finitely, which is the property the
/// engine's vector-row encoder checks before it will store a row.
#[test]
fn every_finished_component_is_exactly_representable_as_finite_f16() {
    let mut raw = vec![0.5f32; DIMS];
    raw[0] = -5.8e-38;
    raw[1] = 1.0e-30;
    let finished = common().finish_vector(raw).expect("finished");
    for (index, &value) in finished.iter().enumerate() {
        let narrowed = half::f16::from_f32(value);
        assert!(narrowed.is_finite(), "component {index} is not finite f16");
        assert_eq!(
            narrowed.to_f32(),
            value,
            "component {index} is not an exact f16 value"
        );
    }
}

// ─── the slot ────────────────────────────────────────────────────────────

fn endpoint_config(endpoint: &str) -> EmbedderConfig {
    EmbedderConfig {
        provider: EmbedderProvider::Endpoint,
        dimensions: DIMS,
        model_id: "test/model@rev".to_owned(),
        endpoint: EndpointEmbedderConfig {
            endpoint: Some(endpoint.to_owned()),
            model_key: Some(MODEL_KEY.to_owned()),
            ..EndpointEmbedderConfig::default()
        },
        ..EmbedderConfig::default()
    }
}

#[test]
fn a_none_provider_builds_no_slot() {
    let config = EmbedderConfig {
        provider: EmbedderProvider::None,
        ..EmbedderConfig::default()
    };
    assert!(
        EmbedderSlot::from_config(&config)
            .expect("none resolves")
            .is_none()
    );
}

#[test]
fn a_query_against_an_unready_slot_is_refused_as_not_ready() {
    let config = EmbedderConfig {
        provider: EmbedderProvider::Local,
        ..EmbedderConfig::default()
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("local resolves")
        .expect("a local slot exists");
    assert!(slot.ready().is_none(), "a local slot loads in the worker");
    assert_eq!(
        slot.embed_query("anything"),
        Err(EmbedQueryRefusal::NotReady)
    );
}

// ─── endpoint provider against a real server ─────────────────────────────

const MODEL_KEY: &str = "test-embedding-model";

/// A loopback port nothing listens on: every fetch against it fails on connect,
/// which is the failure a row about an unreachable model source wants, without
/// a packet leaving the machine.
const UNREACHABLE_MODEL_SOURCE: &str = "http://127.0.0.1:1";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MockBehaviour {
    #[default]
    Ok,
    /// Answer with the rows in reverse, each still carrying its own index.
    Reversed,
    ServerError,
    WrongWidth,
    /// List a model the configured key is not among.
    UnknownModel,
}

struct MockState {
    behaviour: Mutex<MockBehaviour>,
    requests: Mutex<Vec<Value>>,
}

impl MockState {
    fn behaviour(&self) -> MockBehaviour {
        *self.behaviour.lock().expect("mock behaviour lock")
    }
}

struct MockEndpoint {
    base: String,
    state: Arc<MockState>,
    // Dropping the runtime stops the server; the field keeps it alive for the
    // length of the test.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for MockEndpoint {
    fn drop(&mut self) {
        // Shut down without waiting on the still-listening server task.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl MockEndpoint {
    fn start(behaviour: MockBehaviour) -> Self {
        let state = Arc::new(MockState {
            behaviour: Mutex::new(behaviour),
            requests: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/v1/models", get(mock_models))
            .route("/v1/embeddings", post(mock_embeddings))
            .with_state(Arc::clone(&state));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("mock runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("mock listener");
        let addr: SocketAddr = listener.local_addr().expect("mock addr");
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}/v1"),
            state,
            runtime: Some(runtime),
        }
    }

    /// Flips what the server answers, so a row can prove recovery.
    fn set_behaviour(&self, behaviour: MockBehaviour) {
        *self.state.behaviour.lock().expect("mock behaviour lock") = behaviour;
    }

    fn requests(&self) -> Vec<Value> {
        self.state
            .requests
            .lock()
            .expect("mock requests lock")
            .clone()
    }

    fn embedder(&self) -> Arc<endpoint::HttpEmbedder> {
        endpoint::HttpEmbedder::from_config(&endpoint_config(&self.base)).expect("http embedder")
    }
}

async fn mock_models(State(state): State<Arc<MockState>>) -> axum::Json<Value> {
    let id = if state.behaviour() == MockBehaviour::UnknownModel {
        "some-other-model"
    } else {
        MODEL_KEY
    };
    axum::Json(json!({ "data": [{ "id": id }] }))
}

/// The deterministic space the mock embeds into: one axis per input text, so a
/// query whose text equals a document's text scores exactly 1.
fn mock_vector(text: &str, width: usize) -> Vec<f32> {
    let axis = text.bytes().fold(0u64, |acc, byte| {
        acc.wrapping_mul(131).wrapping_add(byte.into())
    }) as usize
        % width;
    let mut vector = vec![0.0f32; width];
    vector[axis] = 1.0;
    vector
}

async fn mock_embeddings(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Result<axum::Json<Value>, StatusCode> {
    state
        .requests
        .lock()
        .expect("mock requests lock")
        .push(body.clone());
    if state.behaviour() == MockBehaviour::ServerError {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let width = if state.behaviour() == MockBehaviour::WrongWidth {
        DIMS + 1
    } else {
        DIMS
    };
    let inputs: Vec<String> = body["input"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| row.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut rows: Vec<Value> = inputs
        .iter()
        .enumerate()
        .map(|(index, text)| json!({ "index": index, "embedding": mock_vector(text, width) }))
        .collect();
    if state.behaviour() == MockBehaviour::Reversed {
        rows.reverse();
    }
    Ok(axum::Json(json!({ "data": rows })))
}

fn summary_input(text: &str) -> oneiron::embed::PendingEmbeddingInput {
    oneiron::embed::PendingEmbeddingInput {
        entity_id: oneiron::entity_id::EntityId::from_bytes([0x7e; 16]).expect("entity id"),
        payload: oneiron::embed::PendingEmbeddingPayload::SummaryText(text.to_owned()),
        pending_embedding_token: vec![1],
    }
}

#[test]
fn the_request_carries_the_model_key_and_the_projected_documents_in_order() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let embedder = mock.embedder();
    let inputs = [summary_input("first text"), summary_input("second text")];
    let vectors = oneiron::embed::Embedder::embed(embedder.as_ref(), &inputs).expect("embedded");
    assert_eq!(vectors.len(), 2);
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["model"], json!(MODEL_KEY));
    assert_eq!(
        requests[0]["input"],
        json!(["first text", "second text"]),
        "documents carry no instruction prefix and keep input order"
    );
}

#[test]
fn a_query_carries_exactly_the_instruction_prefix() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let embedder = mock.embedder();
    embedder
        .embed_query("what did we decide")
        .expect("embedded");
    let requests = mock.requests();
    assert_eq!(
        requests[0]["input"],
        json!([format!(
            "{}what did we decide",
            crate::config::embedder::DEFAULT_QUERY_INSTRUCTION
        )]),
        "a query carries exactly the configured instruction and nothing else"
    );
}

#[test]
fn rows_returned_out_of_order_are_placed_by_their_own_index() {
    let ordered = MockEndpoint::start(MockBehaviour::Ok);
    let reversed = MockEndpoint::start(MockBehaviour::Reversed);
    let inputs = [
        summary_input("alpha"),
        summary_input("beta"),
        summary_input("gamma"),
    ];
    let straight =
        oneiron::embed::Embedder::embed(ordered.embedder().as_ref(), &inputs).expect("embedded");
    let shuffled =
        oneiron::embed::Embedder::embed(reversed.embedder().as_ref(), &inputs).expect("embedded");
    assert_eq!(straight, shuffled, "index decides placement, not row order");
}

#[test]
fn an_http_failure_returns_an_error_after_one_attempt() {
    let mock = MockEndpoint::start(MockBehaviour::ServerError);
    let embedder = mock.embedder();
    let error = oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("text")])
        .expect_err("a 500 fails closed");
    assert!(
        matches!(error, oneiron::Error::UpstreamToolFailure { .. }),
        "{error:?}"
    );
    assert_eq!(
        mock.requests().len(),
        1,
        "the client makes one attempt; the worker loop is the retry"
    );
}

#[test]
fn an_unreachable_endpoint_fails_closed_without_a_vector() {
    // Port 1 on loopback: nothing listens, so this is a connect failure rather
    // than a slow one, and the test needs no timeout to prove it.
    let embedder = endpoint::HttpEmbedder::from_config(&endpoint_config("http://127.0.0.1:1/v1"))
        .expect("built");
    let error = oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("text")])
        .expect_err("an unreachable endpoint fails closed");
    assert!(
        matches!(error, oneiron::Error::UpstreamToolFailure { .. }),
        "{error:?}"
    );
}

#[test]
fn an_over_long_input_is_shortened_and_counted() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let embedder = mock.embedder();
    let config = endpoint_config(&mock.base);
    let cap = config.max_input_tokens * 4;
    let long = "x".repeat(cap * 2);
    oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input(&long)]).expect("embedded");
    let sent = mock.requests()[0]["input"][0]
        .as_str()
        .expect("input text")
        .len();
    assert!(sent <= cap, "sent {sent} bytes for a cap of {cap}");
    assert_eq!(
        QueryEmbedder::truncations(embedder.as_ref()),
        1,
        "the truncation is counted"
    );
}

#[test]
fn a_probe_against_a_reachable_endpoint_of_the_right_width_is_ready() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    assert_eq!(
        endpoint::probe_endpoint(mock.embedder().as_ref()),
        Ok(ProbeOutcome::Ready)
    );
}

#[test]
fn a_probe_naming_both_widths_refuses_a_mismatched_endpoint() {
    let mock = MockEndpoint::start(MockBehaviour::WrongWidth);
    assert_eq!(
        endpoint::probe_endpoint(mock.embedder().as_ref()),
        Err(ProbeError::DimensionMismatch {
            expected: DIMS,
            got: DIMS + 1
        })
    );
}

#[test]
fn a_probe_refuses_an_endpoint_that_does_not_serve_the_model_key() {
    let mock = MockEndpoint::start(MockBehaviour::UnknownModel);
    let error = endpoint::probe_endpoint(mock.embedder().as_ref())
        .expect_err("a reachable endpoint without the model is a config error");
    assert!(
        matches!(error, ProbeError::ModelKeyMissing { ref model_key, .. } if model_key == MODEL_KEY),
        "{error:?}"
    );
}

#[test]
fn a_probe_against_an_unreachable_endpoint_is_not_fatal() {
    let embedder = endpoint::HttpEmbedder::from_config(&endpoint_config("http://127.0.0.1:1/v1"))
        .expect("built");
    assert!(matches!(
        endpoint::probe_endpoint(embedder.as_ref()),
        Ok(ProbeOutcome::Unreachable(_))
    ));
}

/// A pending row that projects to nothing is refused rather than embedded: the
/// alternative is a vector with no meaning that retrieval would then rank.
#[test]
fn an_empty_projection_is_refused() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let embedder = mock.embedder();
    let error = oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("   ")])
        .expect_err("empty text is refused");
    assert!(
        matches!(error, oneiron::Error::InvariantViolation(_)),
        "{error:?}"
    );
    assert!(
        mock.requests().is_empty(),
        "the refusal happens before the wire"
    );
}

// ─── end to end: vault, worker, query door ───────────────────────────────

/// A vault whose width and space match the mock endpoint.
fn test_vault(dir: &std::path::Path) -> Arc<oneiron::Vault> {
    let mut config = oneiron::VaultConfig::device();
    config.dimensions = DIMS;
    config.embedding_model = Some("test/model@rev".to_owned());
    Arc::new(oneiron::Vault::open(dir, config).expect("test vault"))
}

fn claim_body(text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("pred"), rmpv::Value::from("test.status")),
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary([0x7d; 16].to_vec()),
            ),
            (rmpv::Value::from("val"), rmpv::Value::from(text)),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.9)),
            (rmpv::Value::from("appr"), rmpv::Value::from("auto")),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
        ]),
    )
    .expect("encode claim body");
    body
}

fn put_claim(vault: &oneiron::Vault, seed: u8, text: &str) -> oneiron::entity_id::EntityId {
    let mut bytes = [seed; 16];
    bytes[0] = 0x7e;
    let id = oneiron::entity_id::EntityId::from_bytes(bytes).expect("entity id");
    vault
        .batch()
        .put(
            &id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::temporal::TimeRange { start: 1, end: 1 },
            1,
            &claim_body(text),
        )
        .commit()
        .expect("put claim");
    id
}

/// A fresh vault, claims put, the worker run: every pending row gets a vector,
/// and the semantic door finds them and names the provider that filled them.
#[test]
fn the_worker_fills_pending_vectors_and_the_semantic_door_finds_them() {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = test_vault(dir.path());
    let texts = [
        "first claim prose",
        "second claim prose",
        "third claim prose",
    ];
    let ids: Vec<_> = texts
        .iter()
        .enumerate()
        .map(|(index, text)| put_claim(&vault, 0xA0 + index as u8, text))
        .collect();
    for id in &ids {
        assert_eq!(vault.get_vector(id).expect("vector read"), None);
    }

    let slot = EmbedderSlot::from_config(&endpoint_config(&mock.base))
        .expect("slot resolves")
        .expect("an endpoint slot exists");
    let server = Arc::new(
        crate::server::SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server")
        .with_embedder(Some(slot)),
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime");
    let body = runtime.block_on(async {
        let worker = server
            .spawn_embedding_worker()
            .expect("a configured slot starts a worker");
        let filled = wait_for_vectors(&vault, &ids).await;
        worker.abort();
        assert!(filled, "the worker filled every pending vector");

        let response = crate::build_app(Arc::clone(&server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/search/semantic")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "text": texts[1], "limit": 5, "view": "standard" }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("semantic response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("response body");
        serde_json::from_slice::<Value>(&bytes).expect("json body")
    });
    runtime.shutdown_background();

    assert_eq!(body["embedder"]["provider"], json!("endpoint"));
    assert_eq!(body["embedder"]["modelId"], json!("test/model@rev"));
    assert_eq!(body["embedder"]["dimensions"], json!(DIMS));
    let hits: Vec<String> = body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|item| item["id"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        hits.contains(&ids[1].to_hex()),
        "the claim whose text was the query is a hit: {hits:?}"
    );
}

async fn wait_for_vectors(vault: &oneiron::Vault, ids: &[oneiron::entity_id::EntityId]) -> bool {
    for _ in 0..200 {
        let filled = ids
            .iter()
            .all(|id| vault.get_vector(id).ok().flatten().is_some());
        if filled {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// A vault opened at rung 0, populated, then reopened with a provider: the
/// backfill completes without a migration verb. This is the attach path.
#[test]
fn attaching_a_provider_to_a_populated_vault_backfills_every_row() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().expect("vault dir");
    let ids = {
        let mut config = oneiron::VaultConfig::device();
        config.dimensions = DIMS;
        let vault = oneiron::Vault::open(dir.path(), config).expect("rung-0 vault");
        (0..3u8)
            .map(|index| put_claim(&vault, 0xB0 + index, &format!("rung zero claim {index}")))
            .collect::<Vec<_>>()
    };

    let vault = test_vault(dir.path());
    let slot = EmbedderSlot::from_config(&endpoint_config(&mock.base))
        .expect("slot resolves")
        .expect("an endpoint slot exists");
    let embedder = slot.ensure_ready().expect("endpoint is ready at once");
    let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        embedder as Arc<dyn oneiron::embed::Embedder>,
    );
    let mut filled = 0;
    for _ in 0..10 {
        let report = reconciler.reconcile_once().expect("reconcile pass");
        filled += report.filled;
        if report.leased == 0 {
            break;
        }
    }
    assert_eq!(filled, ids.len(), "every pre-existing claim was backfilled");
    for id in &ids {
        assert!(
            vault.get_vector(id).expect("vector read").is_some(),
            "attach backfilled {}",
            id.to_hex()
        );
    }
}

/// Rung 0 answers the semantic door with a 503 naming the capability, not with
/// a silently empty result set.
#[test]
fn the_semantic_door_refuses_with_503_when_no_embedder_is_configured() {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("vault dir");
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("vault"));
    let server = Arc::new(
        crate::server::SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (status, body) = runtime.block_on(async {
        let response = crate::build_app(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/search/semantic")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "text": "anything" }).to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice::<Value>(&bytes).expect("json"),
        )
    });
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], json!("EMBEDDER_UNAVAILABLE"));
}

/// A query is a question. Eight kilobytes of it is a document, and the door says
/// which field and which cap rather than truncating it silently.
#[test]
fn the_semantic_door_refuses_oversized_text_with_413() {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("vault dir");
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("vault"));
    let server = Arc::new(
        crate::server::SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (status, body) = runtime.block_on(async {
        let response = crate::build_app(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/search/semantic")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "text": "q".repeat(9 * 1024) }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice::<Value>(&bytes).expect("json"),
        )
    });
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["code"], json!("PAYLOAD_TOO_LARGE"));
    assert_eq!(body["details"]["field"], json!("text"));
}

/// The worker recovers on its own: a provider that fails its first pass and then
/// starts answering fills the queue with no restart.
#[test]
fn a_provider_that_comes_up_later_fills_without_a_restart() {
    let mock = MockEndpoint::start(MockBehaviour::ServerError);
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = test_vault(dir.path());
    let id = put_claim(&vault, 0xC0, "late provider claim");
    // A short lease on purpose: the failed pass holds the row until its lease
    // expires, which is the engine protecting one row from two embedders. The
    // default 30 s window is longer than this row should wait.
    let slot = EmbedderSlot::from_config(&EmbedderConfig {
        lease_ms: 500,
        idle_interval_ms: 100,
        ..endpoint_config(&mock.base)
    })
    .expect("slot resolves")
    .expect("an endpoint slot exists");
    let server = Arc::new(
        crate::server::SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server")
        .with_embedder(Some(slot)),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime");
    let filled = runtime.block_on(async {
        let worker = server
            .spawn_embedding_worker()
            .expect("a configured slot starts a worker");
        // Wait for the first pass to fail before the provider starts answering,
        // so the row proves recovery rather than a lucky first attempt.
        for _ in 0..100 {
            if !mock.requests().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            vault.get_vector(&id).expect("vector read").is_none(),
            "nothing filled while the provider was failing"
        );
        mock.set_behaviour(MockBehaviour::Ok);
        let filled = wait_for_vectors(&vault, std::slice::from_ref(&id)).await;
        worker.abort();
        filled
    });
    runtime.shutdown_background();
    assert!(
        filled,
        "the worker filled the row after the provider came up"
    );
}

/// A local provider whose artifacts cannot be fetched does not stop the server.
///
/// The vault is already open: writes land, lexical reads answer, and the worker
/// keeps retrying. Only the semantic door refuses, and it says why. The source
/// is a loopback port with nothing listening, so the fetch fails on connect and
/// the row never leaves the host.
#[test]
fn a_local_provider_that_cannot_fetch_its_model_still_serves_lexical_reads() {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    let models = tempfile::tempdir().expect("models dir");
    let dir = tempfile::tempdir().expect("vault dir");
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("vault"));
    let config = EmbedderConfig {
        provider: EmbedderProvider::Local,
        dimensions: 1024,
        local: crate::config::LocalEmbedderConfig {
            repo: "oneiron-dev/no-such-embedding-model".to_owned(),
            revision: "0".repeat(40),
            models_dir: Some(models.path().to_path_buf()),
            ..crate::config::LocalEmbedderConfig::default()
        },
        ..EmbedderConfig::default()
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot resolves")
        .expect("a local slot exists")
        .with_model_source(UNREACHABLE_MODEL_SOURCE);
    assert!(slot.ready().is_none());
    let server = Arc::new(
        crate::server::SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server")
        .with_embedder(Some(slot)),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (text_status, semantic_status) = runtime.block_on(async {
        let worker = server
            .spawn_embedding_worker()
            .expect("a configured slot starts a worker");
        let text = crate::build_app(Arc::clone(&server))
            .oneshot(
                Request::builder()
                    .uri("/api/search/text?query=anything")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("text response");
        let text_status = text.status();
        let _ = to_bytes(text.into_body(), 1 << 20).await;
        let semantic = crate::build_app(Arc::clone(&server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/search/semantic")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "text": "anything" }).to_string()))
                    .expect("request"),
            )
            .await
            .expect("semantic response");
        let semantic_status = semantic.status();
        let _ = to_bytes(semantic.into_body(), 1 << 20).await;
        worker.abort();
        (text_status, semantic_status)
    });
    runtime.shutdown_background();
    assert_eq!(text_status, StatusCode::OK, "lexical reads still answer");
    assert_eq!(
        semantic_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the semantic door refuses until the provider serves"
    );
    assert!(
        !models.path().join("oneiron-dev").exists()
            || std::fs::read_dir(models.path().join("oneiron-dev"))
                .into_iter()
                .flatten()
                .flatten()
                .all(|entry| entry.path().is_dir()),
        "a failed fetch leaves no artifact behind"
    );
}
