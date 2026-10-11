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
    /// Embed into [`concept_vector`]'s meaning space.
    Concepts,
    /// List the model as `embedder serve` does: marked, with its transform,
    /// and answer with that transform.
    OneironWire,
    /// [`Self::OneironWire`] restarted with other settings: it lists and
    /// answers with [`OTHER_TRANSFORM`].
    OneironWireOther,
    /// The listing answers 503.
    ListingDown,
    /// No listing route (404), as many OpenAI-compatible servers have.
    NoListing,
    /// Lists the model as [`Self::OneironWire`] does, but answers with
    /// [`OTHER_TRANSFORM`]: two backends behind one address.
    ListingDisagrees,
}

/// The model the Oneiron-wire behaviours say they loaded, until a row says
/// otherwise ([`MockEndpoint::serve_model`]): [`endpoint_config`]'s.
const MOCK_MODEL: &str = "test/model@rev";
/// The transform the [`MockBehaviour::OneironWire`] listing reports.
const MOCK_TRANSFORM: &str = "attn=bidirectional;pool=mean;mock";
/// The transform [`MockBehaviour::OneironWireOther`] reports.
const OTHER_TRANSFORM: &str = "attn=bidirectional;pool=mean;mock;out=binary";

struct EmbeddingPause {
    request: usize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct MockState {
    pause: Mutex<Option<Arc<EmbeddingPause>>>,
    behaviour: Mutex<MockBehaviour>,
    /// The model the Oneiron-wire behaviours list and answer as loaded.
    model: Mutex<String>,
    /// The profile they list and answer with; none until a row sets one.
    profile: Mutex<Value>,
    /// The device and runtime they answer with; none until a row sets one.
    mark: Mutex<Value>,
    requests: Mutex<Vec<Value>>,
}

impl MockState {
    fn behaviour(&self) -> MockBehaviour {
        *self.behaviour.lock().expect("mock behaviour lock")
    }

    fn model(&self) -> String {
        self.model.lock().expect("mock model lock").clone()
    }

    fn profile(&self) -> Value {
        self.profile.lock().expect("mock profile lock").clone()
    }

    fn mark(&self) -> Value {
        self.mark.lock().expect("mock mark lock").clone()
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
            pause: Mutex::new(None),
            behaviour: Mutex::new(behaviour),
            model: Mutex::new(MOCK_MODEL.to_owned()),
            profile: Mutex::new(Value::Null),
            mark: Mutex::new(Value::Null),
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

    /// Puts another model behind the same key and transform, as a server
    /// restarted on another checkpoint lists and answers it.
    fn serve_model(&self, model: &str) {
        *self.state.model.lock().expect("mock model lock") = model.to_owned();
    }

    /// Runs the model with another profile, as a server restarted with other
    /// settings that leave its transform as it was lists and answers it.
    fn serve_profile(&self, profile: Value) {
        *self.state.profile.lock().expect("mock profile lock") = profile;
    }

    /// Answers as a server computing on `mark`'s device and runtime does.
    fn serve_on(&self, mark: Value) {
        *self.state.mark.lock().expect("mock mark lock") = mark;
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

async fn mock_models(State(state): State<Arc<MockState>>) -> Result<axum::Json<Value>, StatusCode> {
    Ok(match state.behaviour() {
        MockBehaviour::UnknownModel => {
            axum::Json(json!({ "data": [{ "id": "some-other-model" }] }))
        }
        MockBehaviour::ListingDown => return Err(StatusCode::SERVICE_UNAVAILABLE),
        MockBehaviour::NoListing => return Err(StatusCode::NOT_FOUND),
        MockBehaviour::OneironWire
        | MockBehaviour::OneironWireOther
        | MockBehaviour::ListingDisagrees => axum::Json(json!({
            "data": [{
                "id": MODEL_KEY,
                "oneiron_wire": 1,
                "model_id": state.model(),
                "transform": mock_transform(state.behaviour()),
                "profile": state.profile(),
            }]
        })),
        _ => axum::Json(json!({ "data": [{ "id": MODEL_KEY }] })),
    })
}

fn mock_transform(behaviour: MockBehaviour) -> &'static str {
    match behaviour {
        MockBehaviour::OneironWireOther => OTHER_TRANSFORM,
        _ => MOCK_TRANSFORM,
    }
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

/// A tiny meaning space: the words of one concept share an axis, so a
/// paraphrase that shares no word with its document still lands on it. Text
/// with no concept word points along the last axis.
fn concept_vector(text: &str, width: usize) -> Vec<f32> {
    const CONCEPTS: [&[&str]; 3] = [
        &["car", "automobile", "vehicle"],
        &["repair", "mechanic", "garage", "fix"],
        &["lunch", "meal", "noon"],
    ];
    let mut vector = vec![0.0f32; width];
    for word in text
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
    {
        if let Some(axis) = CONCEPTS
            .iter()
            .position(|words| words.contains(&word.as_str()))
        {
            vector[axis] += 1.0;
        }
    }
    if vector.iter().all(|value| *value == 0.0) {
        vector[width - 1] = 1.0;
    }
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    vector.iter().map(|value| value / norm).collect()
}

async fn mock_embeddings(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Result<axum::Json<Value>, StatusCode> {
    let request_number = {
        let mut requests = state.requests.lock().expect("mock requests lock");
        requests.push(body.clone());
        requests.len()
    };
    let pause = state.pause.lock().expect("pause lock").clone();
    if let Some(pause) = pause.filter(|pause| pause.request == request_number) {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
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
        .map(|(index, text)| {
            let embedding = if state.behaviour() == MockBehaviour::Concepts {
                concept_vector(text, width)
            } else {
                mock_vector(text, width)
            };
            json!({ "index": index, "embedding": embedding })
        })
        .collect();
    if state.behaviour() == MockBehaviour::Reversed {
        rows.reverse();
    }
    if matches!(
        state.behaviour(),
        MockBehaviour::OneironWire
            | MockBehaviour::OneironWireOther
            | MockBehaviour::ListingDisagrees
    ) {
        let transform = match state.behaviour() {
            MockBehaviour::ListingDisagrees => OTHER_TRANSFORM,
            behaviour => mock_transform(behaviour),
        };
        return Ok(axum::Json(json!({
            "data": rows,
            "model_id": state.model(),
            "transform": transform,
            "profile": state.profile(),
            "provenance": state.mark(),
        })));
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

/// Against `embedder serve`, whose `/models` rows carry the Oneiron mark, the
/// client sends what a local vault's provider would see: whole documents
/// marked as documents, which the server's tokenizer caps, and a query marked
/// as one with the vault's own instruction beside it rather than in it. And
/// the slot holds the server's transform to the vault's pin: before it is
/// admitted, or refused, the endpoint answers no query, as a local model
/// answers none before it is loaded and admitted.
#[test]
fn an_oneiron_endpoint_gets_whole_marked_texts_and_is_held_to_the_vault_pin() {
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    let config = EmbedderConfig {
        query_instruction: Some("query: ".to_owned()),
        max_input_tokens: 4,
        ..endpoint_config(&mock.base)
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    assert_eq!(
        slot.embed_query("cats"),
        Err(EmbedQueryRefusal::NotReady),
        "no query before the worker admits the endpoint"
    );
    let refused = slot.ensure_ready(|admission| {
        assert_eq!(admission.transform, Some(MOCK_TRANSFORM));
        Err(oneiron::Error::InvalidConfig(
            "the vault pins another transform".to_owned(),
        ))
    });
    assert!(refused.is_err());
    assert_eq!(slot.embed_query("cats"), Err(EmbedQueryRefusal::NotReady));
    let embedder = slot.ensure_ready(|_| Ok(())).expect("admitted");
    let long = "word ".repeat(40);
    oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input(&long)]).expect("embedded");
    slot.embed_query("cats").expect("query embedded");
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0]["input"],
        json!([long]),
        "whole, past the client's cap"
    );
    assert_eq!(requests[0]["input_type"], json!("document"));
    assert_eq!(requests[1]["input"], json!(["cats"]));
    assert_eq!(requests[1]["input_type"], json!("query"));
    assert_eq!(requests[1]["instruction"], json!("query: "));
}

/// Whole texts go to `embedder serve`, so a batch of long ones is split into
/// requests a slow host answers inside the timeout; the vectors come back in
/// input order.
#[test]
fn long_documents_reach_an_oneiron_endpoint_in_several_requests() {
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    let embedder = mock.embedder();
    let texts: Vec<String> = ["a", "b", "c"]
        .iter()
        .map(|word| format!("{word} ").repeat(10 * 1024))
        .collect();
    let inputs: Vec<_> = texts.iter().map(|text| summary_input(text)).collect();
    let vectors = oneiron::embed::Embedder::embed(embedder.as_ref(), &inputs).expect("embedded");
    assert_eq!(mock.requests().len(), 3, "20 KiB each, two never share one");
    for (vector, text) in vectors.iter().zip(&texts) {
        assert_eq!(*vector, mock_vector(text, DIMS), "in input order");
    }
}

/// The vault holds `embedder serve` to the transform it admitted for as long
/// as it runs: a listing that fails is not taken for a plain OpenAI server, a
/// server restarted with other settings fills and answers nothing, and once
/// restored it is admitted again without a vault restart.
#[test]
fn an_oneiron_endpoint_that_changes_how_it_embeds_is_refused_until_restored() {
    let mock = MockEndpoint::start(MockBehaviour::ListingDown);
    let slot = EmbedderSlot::from_config(&endpoint_config(&mock.base))
        .expect("slot")
        .expect("active");
    let pinned = |admission: Admission<'_>| {
        if admission.transform == Some(MOCK_TRANSFORM) {
            Ok(())
        } else {
            Err(oneiron::Error::InvalidConfig(
                "the vault pins another transform".to_owned(),
            ))
        }
    };
    assert!(
        slot.ensure_ready(pinned).is_err(),
        "a listing that answers 503 admits nothing"
    );
    mock.set_behaviour(MockBehaviour::OneironWireOther);
    assert!(
        slot.ensure_ready(pinned).is_err(),
        "another transform is refused"
    );
    assert_eq!(slot.embed_query("cats"), Err(EmbedQueryRefusal::NotReady));
    mock.set_behaviour(MockBehaviour::OneironWire);
    let embedder = slot.ensure_ready(pinned).expect("restored, admitted");
    oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("first")])
        .expect("embedded");
    assert_eq!(
        mock.requests().last().expect("a request")["input_type"],
        json!("document"),
        "the failed listing was not cached as the OpenAI wire"
    );
    mock.set_behaviour(MockBehaviour::OneironWireOther);
    assert!(
        oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("second")]).is_err(),
        "vectors made another way are not stored"
    );
    assert_eq!(slot.embed_query("cats"), Err(EmbedQueryRefusal::Failed));
    mock.set_behaviour(MockBehaviour::OneironWire);
    oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("third")])
        .expect("restored");
}

/// Another revision of [`MOCK_MODEL`]: the same architecture, other weights.
const OTHER_REVISION: &str = "test/model@rev2";

/// Review P1 (Astra, #1361): a shared alias restarted on another revision of
/// the same architecture truthfully lists and answers the same transform. Bug
/// repro: the vault held answers to the transform alone, so it stored the new
/// revision's vectors in the old one's space. The model the server loaded is
/// now held to the vault's at admission, in every answer, after a restart
/// and for a move; nothing it makes is stored, and no query is answered.
#[test]
fn an_alias_moved_to_another_revision_is_refused_and_nothing_is_stored() {
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = test_vault(dir.path());
    let config = endpoint_config(&mock.base);
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    let admit = |admission: Admission<'_>| admission.into_vault(&vault);
    let embedder = slot
        .ensure_ready(admit)
        .expect("the vault's model, admitted");
    let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        embedder as Arc<dyn oneiron::embed::Embedder>,
    );
    let first = put_claim(&vault, 0xE1, "a claim the first revision embeds");
    while reconciler.reconcile_once().expect("filled").leased > 0 {}
    assert!(vault.get_vector(&first).expect("read").is_some());
    slot.embed_query("cats").expect("a query answered");

    mock.serve_model(OTHER_REVISION);
    let second = put_claim(&vault, 0xE2, "a claim the second revision answers");
    assert!(
        reconciler.reconcile_once().is_err(),
        "an answer from another model is refused"
    );
    assert_eq!(vault.get_vector(&second).expect("read"), None);
    assert_eq!(slot.embed_query("cats"), Err(EmbedQueryRefusal::Failed));
    let refused = slot.ensure_ready(admit).err().map(|error| error.kind());
    assert_eq!(refused, Some(oneiron::ErrorKind::EmbeddingModelChanged));
    assert_eq!(slot.embed_query("cats"), Err(EmbedQueryRefusal::NotReady));

    let restarted = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    assert!(
        restarted.ensure_ready(admit).is_err(),
        "nor after a restart"
    );
    assert!(
        endpoint::resolve_transform(&config).is_err(),
        "nor as the space a vault on the first revision moves to"
    );
    let moved = EmbedderConfig {
        model_id: OTHER_REVISION.to_owned(),
        ..config
    };
    assert_eq!(
        endpoint::resolve_transform(&moved).expect("a move to the served revision"),
        Some(MOCK_TRANSFORM.to_owned())
    );
}

/// Review R7-2 (Sol, the P1 fix): a remote rung is a second door to the
/// vault's vectors. Bug repro: it was never admitted, so a rung on a shared
/// alias that came back with another revision behind it still had its answers
/// stored. Its answers are now held to the vault's model and to the transform
/// the vault admitted from its provider; a refused answer falls back to the
/// provider, as any failed remote answer does. Each vector is marked with the
/// endpoint that answered for it (ARCH-0036), never the one first asked.
#[test]
fn a_remote_rung_on_an_alias_moved_to_another_revision_is_refused() {
    use oneiron::embed::{EmbedderLocality, EmbeddingDevice, EmbeddingProvenance};
    let answered_by = |base: &str| {
        EmbeddingProvenance::new(EmbeddingDevice::Remote, format!("{MODEL_KEY}@{base}"))
    };
    let primary = MockEndpoint::start(MockBehaviour::OneironWire);
    let remote = MockEndpoint::start(MockBehaviour::OneironWire);
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = test_vault(dir.path());
    let config = EmbedderConfig {
        remote: Some(owner_rung(&remote.base)),
        ..endpoint_config(&primary.base)
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    let embedder = slot
        .ensure_ready(|admission| admission.into_vault(&vault))
        .expect("admitted");
    let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        embedder as Arc<dyn oneiron::embed::Embedder>,
    )
    .with_remote_rung(
        slot.remote_rung(receipts())
            .expect("rung")
            .expect("configured"),
    )
    .expect("rung");
    while reconciler.reconcile_once().expect("filled").leased > 0 {}
    let first = put_claim(&vault, 0xE5, "a claim the rung embeds");
    let report = reconciler.reconcile_once().expect("filled");
    assert_eq!((report.routed_remote, report.filled), (1, 1));
    assert_eq!(
        vault.embedding_locality(&first).expect("read"),
        Some(EmbedderLocality::OwnerServer)
    );
    assert_eq!(
        vault.embedding_provenance(&first).expect("read"),
        Some(answered_by(&remote.base))
    );

    remote.serve_model(OTHER_REVISION);
    let second = put_claim(&vault, 0xE6, "a claim the moved alias would embed");
    let report = reconciler.reconcile_once().expect("filled");
    assert_eq!(
        (report.remote_failed_fallback_local, report.filled),
        (1, 1),
        "refused, and filled by the vault's own provider"
    );
    assert_eq!(
        vault.embedding_locality(&second).expect("read"),
        Some(EmbedderLocality::OnDevice)
    );
    assert_eq!(
        vault.embedding_provenance(&second).expect("read"),
        Some(answered_by(&primary.base))
    );
}

/// The owner's ruling (EMBED-DEVICE, ARCH-0036): behind a shared endpoint a
/// vault still marks each vector with the device that computed it, so a CPU's
/// vectors and a GPU's are told apart and one set can be patched. Each answer
/// of `embedder serve` names its device and runtime; an endpoint that does not
/// say, or names no device it ran on or a runtime unfit to store, is marked
/// `remote`.
#[test]
fn vectors_from_a_cpu_endpoint_and_a_cuda_endpoint_are_marked_apart() {
    use oneiron::embed::{EmbeddingDevice, EmbeddingProvenance};
    let on_cpu = EmbeddingProvenance::new(EmbeddingDevice::Cpu, "candle 0.11.0 q8_0 x86_64+avx2");
    let on_cuda = EmbeddingProvenance::new(EmbeddingDevice::Cuda, "candle 0.11.0 q8_0");
    let cpu = MockEndpoint::start(MockBehaviour::OneironWire);
    cpu.serve_on(serde_json::to_value(&on_cpu).expect("mark"));
    let cuda = MockEndpoint::start(MockBehaviour::OneironWire);
    cuda.serve_on(serde_json::to_value(&on_cuda).expect("mark"));
    let silent = MockEndpoint::start(MockBehaviour::OneironWire);
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = test_vault(dir.path());
    let fill_from = |endpoint: &MockEndpoint| {
        let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
            Arc::clone(&vault),
            endpoint.embedder() as Arc<dyn oneiron::embed::Embedder>,
        );
        let mut filled = 0;
        loop {
            let report = reconciler.reconcile_once().expect("filled");
            if report.leased == 0 {
                return filled;
            }
            filled += report.filled;
        }
    };
    fill_from(&silent);
    let first = put_claim(&vault, 0xE7, "a claim the CPU endpoint embeds");
    assert_eq!(fill_from(&cpu), 1);
    let second = put_claim(&vault, 0xE8, "a claim the CUDA endpoint embeds");
    assert_eq!(fill_from(&cuda), 1);
    assert_eq!(vault.embedding_provenance(&first).expect("read"), Some(on_cpu));
    assert_eq!(vault.embedding_provenance(&second).expect("read"), Some(on_cuda));
    // The doctor's selection (`oneiron doctor --vectors-from <device>`).
    assert_eq!(
        vault.vectors_by_provenance(EmbeddingDevice::Cpu, None).expect("cpu"),
        vec![first]
    );
    assert_eq!(
        vault.vectors_by_provenance(EmbeddingDevice::Cuda, None).expect("cuda"),
        vec![second]
    );

    silent.serve_on(json!({ "device": "cuda", "runtime": "x".repeat(129) }));
    let third = put_claim(&vault, 0xE9, "a claim an endpoint marks unfit to store");
    assert_eq!(fill_from(&silent), 1);
    let remote = EmbeddingProvenance::new(
        EmbeddingDevice::Remote,
        format!("{MODEL_KEY}@{}", silent.base),
    );
    assert_eq!(vault.embedding_provenance(&third).expect("read"), Some(remote));
    assert_eq!(
        vault.vectors_by_provenance(EmbeddingDevice::Cuda, None).expect("cuda"),
        vec![second]
    );
}

/// A remote rung on the owner's server at `endpoint`, every row allowed out.
fn owner_rung(endpoint: &str) -> crate::config::remote_embedder::RemoteEmbedderConfig {
    use crate::config::remote_embedder::{EgressPolicy, RemoteEmbedderConfig};
    RemoteEmbedderConfig {
        endpoint: endpoint.to_owned(),
        model_key: MODEL_KEY.into(),
        locality: crate::config::EmbedderLocality::OwnerServer,
        artifact: None,
        api_key_env: None,
        lease_ms: 120_000,
        timeout_ms: 1000,
        egress: Some(EgressPolicy {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_all: true,
        }),
    }
}

/// Review (Astra's re-check, #1361): a remote rung fills rows the vault
/// judges by its floors. Bug repro: a rung's answers were held to the model
/// and transform alone, and weight precision is not in the transform, so a
/// rung on unquantised weights filled a vault judged by the floors measured
/// for Q8_0. Under measured floors a rung's answers must now name a measured
/// profile, or the vault's own provider fills the row.
#[test]
fn a_remote_rung_off_the_measured_profile_is_refused_under_measured_floors() {
    use oneiron::embed::EmbedderLocality;
    let shipped_id = crate::config::embedder::DEFAULT_MODEL_ID;
    let primary = MockEndpoint::start(MockBehaviour::OneironWire);
    let remote = MockEndpoint::start(MockBehaviour::OneironWire);
    primary.serve_model(shipped_id);
    primary.serve_profile(shipped_profile(json!({})));
    remote.serve_model(shipped_id);
    remote.serve_profile(shipped_profile(json!({ "quant": "none" })));
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = vault_on(dir.path(), shipped_id);
    let config = EmbedderConfig {
        model_id: shipped_id.to_owned(),
        remote: Some(owner_rung(&remote.base)),
        ..endpoint_config(&primary.base)
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    let embedder = slot
        .ensure_ready(|admission| admission.into_vault(&vault))
        .expect("admitted");
    assert_eq!(vault.vector_evidence(), MEASURED);
    let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        embedder as Arc<dyn oneiron::embed::Embedder>,
    )
    .with_remote_rung(
        slot.remote_rung(receipts())
            .expect("rung")
            .expect("configured"),
    )
    .expect("rung");
    while reconciler.reconcile_once().expect("filled").leased > 0 {}

    let first = put_claim(&vault, 0xE7, "a claim the unquantised rung would embed");
    let report = reconciler.reconcile_once().expect("filled");
    assert_eq!(
        (report.remote_failed_fallback_local, report.filled),
        (1, 1),
        "refused, and filled by the vault's own provider"
    );
    assert_eq!(
        vault.embedding_locality(&first).expect("read"),
        Some(EmbedderLocality::OnDevice)
    );

    // A longer input cap still reads what the shipped one does.
    remote.serve_profile(shipped_profile(json!({ "max_input_tokens": 8192 })));
    let second = put_claim(&vault, 0xE8, "a claim the measured rung embeds");
    let report = reconciler.reconcile_once().expect("filled");
    assert_eq!((report.routed_remote, report.filled), (1, 1));
    assert_eq!(
        vault.embedding_locality(&second).expect("read"),
        Some(EmbedderLocality::OwnerServer)
    );
}

/// The profile `embedder serve` lists for the shipped model run as it was
/// measured, with `changed` over it.
fn shipped_profile(changed: Value) -> Value {
    let mut profile = json!({
        "model_dir": false,
        "quant": "q8_0",
        "attention": "auto",
        "output_quantization": "int8",
        "max_input_tokens": crate::config::embedder::DEFAULT_MAX_INPUT_TOKENS,
    });
    if let (Some(profile), Some(changed)) = (profile.as_object_mut(), changed.as_object()) {
        profile.extend(changed.clone());
    }
    profile
}

/// The shipped model's measured floors.
const MEASURED: oneiron::config::VectorEvidenceFloors = oneiron::config::VectorEvidenceFloors {
    floor: 0.15,
    strong: 0.25,
};

/// Review P3 (Astra, #1361): a shipped model's measured floors hold only for
/// the profile they were measured under. Bug repro: an endpoint vault took
/// them from its own `model_id` alone, so a server running the shipped model
/// with binary output, which no one measured, was judged by them while a
/// local vault on the same settings was not. A vault now takes its floors
/// when it admits the server, from the model and profile the server names,
/// by the local provider's rule; a profile it cannot read, or none, keeps the
/// engine's default.
#[test]
fn an_endpoint_takes_measured_floors_only_for_the_profile_they_were_measured_with() {
    let shipped_id = crate::config::embedder::DEFAULT_MODEL_ID;
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    mock.serve_model(shipped_id);
    let shipped = EmbedderConfig {
        model_id: shipped_id.to_owned(),
        ..endpoint_config(&mock.base)
    };
    let floors = |profile: Value, config: &EmbedderConfig| {
        mock.serve_profile(profile);
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = vault_on(dir.path(), shipped_id);
        EmbedderSlot::from_config(config)
            .expect("slot")
            .expect("active")
            .ensure_ready(|admission| admission.into_vault(&vault))
            .expect("admitted");
        vault.vector_evidence()
    };
    assert_eq!(floors(shipped_profile(json!({})), &shipped), MEASURED);
    let blank = EmbedderConfig {
        query_instruction: Some(" \n".to_owned()),
        ..shipped.clone()
    };
    assert_eq!(floors(shipped_profile(json!({})), &blank), MEASURED);
    let default = oneiron::config::VectorEvidenceFloors::default();
    for changed in [
        json!({ "output_quantization": "binary" }),
        json!({ "quant": "none" }),
        json!({ "attention": "causal" }),
        json!({ "attention": "bidirectional" }),
        json!({ "max_input_tokens": 8 }),
        json!({ "model_dir": true }),
        json!({ "quant": "a precision this build does not know" }),
    ] {
        assert_eq!(
            floors(shipped_profile(changed.clone()), &shipped),
            default,
            "{changed}"
        );
    }
    assert_eq!(floors(Value::Null, &shipped), default, "no profile listed");
    let prompted = EmbedderConfig {
        query_instruction: Some("Represent this query: ".to_owned()),
        ..shipped
    };
    assert_eq!(floors(shipped_profile(json!({})), &prompted), default);
}

/// A server restarted with another profile and the same transform keeps
/// serving the vault, judged by the floors that profile takes: its answers
/// are refused until the worker admits it again, and then fill.
#[test]
fn a_server_back_with_another_profile_is_admitted_again_with_its_floors() {
    let shipped_id = crate::config::embedder::DEFAULT_MODEL_ID;
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    mock.serve_model(shipped_id);
    mock.serve_profile(shipped_profile(json!({})));
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = vault_on(dir.path(), shipped_id);
    let config = EmbedderConfig {
        model_id: shipped_id.to_owned(),
        idle_interval_ms: 20,
        // A refused answer's row is leased again after this, inside the
        // worker's first backoff.
        lease_ms: 1_000,
        ..endpoint_config(&mock.base)
    };
    let slot = EmbedderSlot::from_config(&config)
        .expect("slot")
        .expect("active");
    let server = Arc::new(
        crate::server::SyncServer::new(Arc::clone(&vault), Default::default())
            .expect("sync server")
            .with_embedder(Some(slot)),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime");
    runtime.block_on(async {
        let worker = server.spawn_embedding_worker().expect("a worker");
        let first = put_claim(&vault, 0xE3, "a claim the measured profile embeds");
        assert!(wait_for_vectors(&vault, &[first]).await, "filled");
        assert_eq!(vault.vector_evidence(), MEASURED);

        mock.serve_profile(shipped_profile(json!({ "output_quantization": "binary" })));
        let second = put_claim(&vault, 0xE4, "a claim the binary profile embeds");
        let filled = wait_for_vectors(&vault, &[second]).await;
        worker.abort();
        assert!(filled, "admitted again and filled");
        assert_eq!(
            vault.vector_evidence(),
            oneiron::config::VectorEvidenceFloors::default()
        );
    });
    runtime.shutdown_background();
}

/// An endpoint has no model files to read a prompt from: a query carries
/// exactly the configured instruction, and nothing when none is configured,
/// whichever model the space names.
#[test]
fn a_query_carries_exactly_the_configured_instruction() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    for (model_id, configured) in [
        (
            "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee",
            None,
        ),
        (crate::config::embedder::DEFAULT_MODEL_ID, None),
        ("test/model@rev", Some("Represent this question: ")),
    ] {
        let config = EmbedderConfig {
            model_id: model_id.to_owned(),
            query_instruction: configured.map(str::to_owned),
            ..endpoint_config(&mock.base)
        };
        endpoint::HttpEmbedder::from_config(&config)
            .expect("http embedder")
            .embed_query("what did we decide")
            .expect("embedded");
        assert_eq!(
            mock.requests().last().expect("a request")["input"],
            json!([format!(
                "{}what did we decide",
                configured.unwrap_or_default()
            )]),
            "{model_id}: a query carries exactly its instruction and nothing else"
        );
    }
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

const PROXY_CHILD: &str = "ONEIRON_TEST_EMBEDDER_PROXY_CHILD";
const PROXY_CHECKED: &str = "embedder proxy isolation checked";
const PROXY_KEY_ENV: &str = "ONEIRON_TEST_EMBEDDER_PROXY_KEY";

/// The endpoint client takes no proxy from the environment or the system:
/// with every proxy variable naming a recording listener and no exclusion,
/// the listing, the probe and an embedding all reach the embedder, and the
/// listener records nothing, so neither the bearer key nor a text passes it.
/// Only a child process carries the variables, so no sibling test sees them.
#[test]
fn the_endpoint_client_never_routes_through_an_inherited_proxy() {
    use std::io::{Read, Write};
    if std::env::var_os(PROXY_CHILD).is_some() {
        let mock = MockEndpoint::start(MockBehaviour::Ok);
        let mut config = endpoint_config(&mock.base);
        config.endpoint.api_key_env = Some(PROXY_KEY_ENV.to_owned());
        // reembed's resolution reads the listing and probes; the worker embeds.
        endpoint::resolve_transform(&config).expect("listing and probe");
        let embedder = endpoint::HttpEmbedder::from_config(&config).expect("http embedder");
        oneiron::embed::Embedder::embed(embedder.as_ref(), &[summary_input("a private note")])
            .expect("embedded");
        assert!(
            mock.requests()
                .iter()
                .any(|request| request["input"] == json!(["a private note"]))
        );
        println!("{PROXY_CHECKED}");
        return;
    }
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("proxy addr"));
    let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let recorded = Arc::clone(&recorded);
        std::thread::spawn(move || {
            for stream in proxy.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                let mut head = [0_u8; 4096];
                let read = stream.read(&mut head).unwrap_or(0);
                recorded
                    .lock()
                    .expect("proxy record")
                    .push(String::from_utf8_lossy(&head[..read]).into_owned());
                let _ = stream.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
    }
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"));
    child.args([
        "--exact",
        "embedder::tests::the_endpoint_client_never_routes_through_an_inherited_proxy",
        "--nocapture",
        "--test-threads=1",
    ]);
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env(name, &proxy_url);
    }
    // No exclusion, and no CGI marker that would switch the proxy off.
    for name in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
        child.env_remove(name);
    }
    child
        .env(PROXY_CHILD, "1")
        .env(PROXY_KEY_ENV, "synthetic-key");
    let output = child.output().expect("child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        *recorded.lock().expect("proxy record"),
        Vec::<String>::new(),
        "an embedder request went to the proxy"
    );
    assert!(
        output.status.success(),
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A mistyped --exact filter exits successfully having run nothing.
    assert!(stdout.contains(PROXY_CHECKED), "{stdout}");
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

/// Review R4-3: a remote with no listing route is the OpenAI wire with an
/// unknown catalog. Bug repro: the probe called it unreachable, so `reembed`
/// refused to move a vault to it; it now checks its width.
#[test]
fn a_remote_with_no_listing_route_is_probed_at_its_width() {
    let mock = MockEndpoint::start(MockBehaviour::NoListing);
    assert!(matches!(
        endpoint::probe_endpoint(mock.embedder().as_ref()),
        Ok(ProbeOutcome::Ready)
    ));
    assert_eq!(
        endpoint::resolve_transform(&endpoint_config(&mock.base)).expect("resolved"),
        None
    );
}

/// Review R4-4: a vault moves to the transform an answer came from. Bug
/// repro: the probe's answer was held to nothing and the listing was read
/// again after it, so a remote whose listing names one transform while its
/// answers carry another moved the vault to the listed one.
#[test]
fn a_move_is_refused_when_the_answers_do_not_carry_the_listed_transform() {
    let mock = MockEndpoint::start(MockBehaviour::ListingDisagrees);
    endpoint::resolve_transform(&endpoint_config(&mock.base))
        .expect_err("answers from another transform than the listed one");
    mock.set_behaviour(MockBehaviour::OneironWire);
    assert_eq!(
        endpoint::resolve_transform(&endpoint_config(&mock.base)).expect("resolved"),
        Some(MOCK_TRANSFORM.to_owned())
    );
}

/// Review R4-1: a vault on the shipped model takes its measured evidence
/// floors, which were measured with unprompted queries. Bug repro: with no
/// instruction of its own the vault sent none, so the shared server's own
/// query prompt applied.
#[test]
fn a_vault_on_the_shipped_model_sends_its_queries_unprompted() {
    let mock = MockEndpoint::start(MockBehaviour::OneironWire);
    let shipped = EmbedderConfig {
        model_id: crate::config::embedder::DEFAULT_MODEL_ID.to_owned(),
        ..endpoint_config(&mock.base)
    };
    for config in [shipped, endpoint_config(&mock.base)] {
        endpoint::HttpEmbedder::from_config(&config)
            .expect("http embedder")
            .embed_query("cats")
            .expect("query embedded");
    }
    let requests = mock.requests();
    assert_eq!(requests[0]["instruction"], json!(""));
    assert_eq!(
        requests[1].get("instruction"),
        None,
        "another model's vault leaves the server's query prompt to it"
    );
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
    vault_on(dir, MOCK_MODEL)
}

/// A vault of the mock endpoint's width in `model`'s space.
fn vault_on(dir: &std::path::Path, model: &str) -> Arc<oneiron::Vault> {
    let mut config = oneiron::VaultConfig::device();
    config.dimensions = DIMS;
    config.embedding_model = Some(model.to_owned());
    Arc::new(oneiron::Vault::open(dir, config).expect("test vault"))
}

fn claim_body(text: &str) -> Vec<u8> {
    // Hand-encoded CLAIM bodies must carry the full v2 scope stamp: the
    // write door rejects a body that misses one of the four scope keys or
    // the version. The subject's substrate mask is derived exactly as the
    // typed `ClaimBody::new` constructor derives it.
    let subject = oneiron::EntityId::from_bytes([0x7d; 16]).expect("subject id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("pred"), rmpv::Value::from("test.status")),
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary(subject.as_bytes().to_vec()),
            ),
            (rmpv::Value::from("val"), rmpv::Value::from(text)),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.9)),
            (rmpv::Value::from("appr"), rmpv::Value::from("auto")),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
            (
                rmpv::Value::from("worldId"),
                rmpv::Value::Binary(oneiron::claim::base_world_id().as_bytes().to_vec()),
            ),
            (
                rmpv::Value::from("scopeRelationshipId"),
                rmpv::Value::from("all"),
            ),
            (
                rmpv::Value::from("scopeFacetId"),
                rmpv::Value::Binary(
                    oneiron::claim::substrate_facet_id(subject)
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                ),
            ),
            (
                rmpv::Value::from("scopeProjectId"),
                rmpv::Value::Binary(oneiron::claim::default_project_id().as_bytes().to_vec()),
            ),
            (rmpv::Value::from("scopeVersion"), rmpv::Value::from(2u64)),
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
    let config_path = dir.path().join("oneiron.toml");
    crate::commands::init(crate::cli::InitArgs {
        path: dir.path().join("vault"),
        config: Some(config_path.clone()),
        embedder: Some(EmbedderProvider::Endpoint),
        embedder_endpoint: Some(mock.base.clone()),
        embedder_model_id: Some("test/model@rev".into()),
        embedder_model_key: Some(MODEL_KEY.into()),
        dimensions: Some(DIMS),
        map_size: 64 * 1024 * 1024,
        ..Default::default()
    })
    .unwrap();
    let serve_config = crate::config::resolve_serve_config_with_sources(
        &crate::config::ServeArgs {
            config: Some(config_path),
            ..Default::default()
        },
        crate::config::EnvConfig::default(),
        None,
    )
    .unwrap();
    let vault = Arc::new(
        oneiron::Vault::open_owned(&serve_config.vault_path, serve_config.vault_config()).unwrap(),
    );
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

    // The mock returns identical vectors, so admit the whole known corpus;
    // this test proves the semantic door, not tie-breaking against seed rows.
    let corpus_size = vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .expect("claim census")
        .len();
    let slot = EmbedderSlot::from_config(serve_config.embedder.as_ref().unwrap())
        .expect("slot resolves")
        .expect("an endpoint slot exists");
    // The semantic door is an owner-grade `/api/*` route over a proof-backed
    // scoped read: it needs a holder-bound owner slip minted by the host.
    // The dev hatch authenticates but carries no proof, so its reads deny.
    let server = Arc::new(
        crate::server::SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                auth_secret: Some("embedder-fixture-secret".to_owned()),
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

        let (slip, key) = crate::test_credentials::credential(&server, "jti=embedder-semantic");
        let response = crate::build_app(Arc::clone(&server))
            .oneshot(crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &key,
                Request::builder()
                    .method("POST")
                    .uri("/api/search/semantic")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "text": texts[1], "limit": corpus_size, "view": "standard" })
                            .to_string(),
                    ))
                    .expect("request"),
            ))
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
        for index in 0..3u8 {
            put_claim(&vault, 0xB0 + index, &format!("rung zero claim {index}"));
        }
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
            .expect("all pre-existing claims")
    };

    let vault = test_vault(dir.path());
    assert_eq!(vault.cold_attach_embedder().unwrap(), ids.len());
    assert_eq!(vault.cold_attach_embedder().unwrap(), 0);
    let slot = EmbedderSlot::from_config(&endpoint_config(&mock.base))
        .expect("slot resolves")
        .expect("an endpoint slot exists");
    let embedder = slot
        .ensure_ready(|_| Ok(()))
        .expect("endpoint is ready at once");
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

/// A run receipt sink for a rung whose rows a test does not read.
fn receipts() -> Arc<dyn oneiron::llm::run_admission::RunReceiptSink> {
    Arc::new(oneiron::llm::run_admission::MemoryReceipts::default())
}

/// Each remote batch's run rows in order, as its reserved and its settled
/// units. Every row is the rung's connector's, and every batch settled.
fn remote_batches(receipts: &oneiron::llm::run_admission::MemoryReceipts) -> Vec<(u64, u64)> {
    use oneiron::llm::run_admission::RunEvent;
    let mut reserved = std::collections::BTreeMap::new();
    let mut batches = Vec::new();
    for row in receipts.rows() {
        match row.event {
            RunEvent::Admitted(facts) => {
                assert_eq!(facts.subject, format!("embedder:{MODEL_KEY}"));
                reserved.insert(facts.lease, facts.reserved_units);
            }
            RunEvent::Settled { lease, units, .. } => {
                batches.push((reserved.remove(&lease).expect("admitted first"), units));
            }
            other => panic!("not a batch's admission or settlement: {other:?}"),
        }
    }
    assert!(reserved.is_empty(), "a batch never settled: {reserved:?}");
    batches
}

#[test]
fn remote_rung_routes_each_entity_and_falls_back_with_truthful_locality() {
    use crate::config::{
        EmbedderLocality as Locality,
        remote_embedder::{EgressPolicy, RemoteEmbedderConfig},
    };
    use oneiron::embed::{EmbedderLocality, PendingEmbeddingReconciler};
    for locality in [Locality::OwnerServer, Locality::ThirdParty] {
        let local = MockEndpoint::start(MockBehaviour::Ok);
        let remote = MockEndpoint::start(MockBehaviour::Ok);
        let dir = tempfile::tempdir().unwrap();
        let vault = test_vault(dir.path());
        let seeded = vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
            .unwrap()
            .len();
        let allow = put_claim(&vault, 0x91, "allow this row");
        let deny = put_claim(&vault, 0x92, "deny this row");
        let unknown = put_claim(&vault, 0x93, "no verdict row");
        let mut late = [0x94; 16];
        late[0] = 0x7e;
        let late = oneiron::EntityId::from_bytes(late).unwrap();
        let mut config = endpoint_config(&local.base);
        config.remote = Some(RemoteEmbedderConfig {
            endpoint: remote.base.clone(),
            model_key: MODEL_KEY.into(),
            locality,
            artifact: None,
            api_key_env: None,
            lease_ms: 120_000,
            timeout_ms: 1000,
            egress: Some(EgressPolicy {
                allow: vec![allow.to_hex(), late.to_hex()],
                deny: vec![deny.to_hex()],
                allow_all: false,
            }),
        });
        let primary = endpoint::HttpEmbedder::from_config(&config).unwrap();
        let receipts = Arc::new(oneiron::llm::run_admission::MemoryReceipts::default());
        let rung = build_remote_rung(&config, Default::default(), receipts.clone())
            .unwrap()
            .unwrap();
        assert_eq!(rung.lease_duration_ms, 120_000);
        let reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), primary)
            .with_remote_rung(rung)
            .unwrap();
        let report = reconciler.reconcile_once().unwrap();
        assert_eq!(
            (
                report.routed_remote,
                report.egress_denied,
                report.egress_no_verdict,
                report.filled
            ),
            (1, 1, 1 + seeded, 3 + seeded)
        );
        let expected = if locality == Locality::OwnerServer {
            EmbedderLocality::OwnerServer
        } else {
            EmbedderLocality::ThirdParty
        };
        assert_eq!(vault.embedding_locality(&allow).unwrap(), Some(expected));
        assert_eq!(
            vault.embedding_locality(&deny).unwrap(),
            Some(EmbedderLocality::OnDevice)
        );
        assert_eq!(
            vault.embedding_locality(&unknown).unwrap(),
            Some(EmbedderLocality::OnDevice)
        );
        // The one remote batch was a paid call, settled at its reservation.
        let sent = remote.requests().len();
        let answered = remote_batches(&receipts);
        assert!(
            matches!(answered.as_slice(), [(reserved, settled)] if reserved == settled && *reserved > 0)
        );
        remote.set_behaviour(MockBehaviour::ServerError);
        assert_eq!(
            put_claim(&vault, 0x94, "row put while remote is down"),
            late
        );
        let report = reconciler.reconcile_once().unwrap();
        assert_eq!((report.remote_failed_fallback_local, report.filled), (1, 1));
        // The failed batch went out, so it keeps its reservation as spend.
        assert!(remote.requests().len() > sent);
        let batches = remote_batches(&receipts);
        assert!(matches!(batches.as_slice(), [_, (reserved, settled)] if reserved == settled));
        assert_eq!(
            vault.embedding_locality(&late).unwrap(),
            Some(EmbedderLocality::OnDevice)
        );
        assert_eq!(reconciler.reconcile_once().unwrap().filled, 0);
    }
}

/// A remote rung's config for `base`, letting `allow` leave.
fn remote_section(
    base: &str,
    allow: oneiron::EntityId,
) -> crate::config::remote_embedder::RemoteEmbedderConfig {
    crate::config::remote_embedder::RemoteEmbedderConfig {
        endpoint: base.to_owned(),
        model_key: MODEL_KEY.into(),
        locality: crate::config::EmbedderLocality::ThirdParty,
        artifact: None,
        api_key_env: None,
        lease_ms: 120_000,
        timeout_ms: 1000,
        egress: Some(crate::config::remote_embedder::EgressPolicy {
            allow: vec![allow.to_hex()],
            deny: Vec::new(),
            allow_all: false,
        }),
    }
}

/// Astra F1 on #1382: the served remote rung sent each batch with no run
/// permit and no run rows. On the serve path, each remote batch is now a
/// paid call admitted and settled on the server's run receipts.
#[test]
fn the_served_remote_rung_admits_and_settles_each_batch() {
    let local = MockEndpoint::start(MockBehaviour::Ok);
    let remote = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().unwrap();
    let vault = test_vault(dir.path());
    let id = put_claim(&vault, 0x96, "a row the owner lets leave");
    let mut config = EmbedderConfig {
        idle_interval_ms: 20,
        ..endpoint_config(&local.base)
    };
    config.remote = Some(remote_section(&remote.base, id));
    let receipts = Arc::new(oneiron::llm::run_admission::MemoryReceipts::default());
    let slot = EmbedderSlot::from_config(&config).unwrap().unwrap();
    let server = Arc::new(
        crate::server::SyncServer::new(Arc::clone(&vault), Default::default())
            .unwrap()
            .with_embedder(Some(slot))
            .with_run_receipts(receipts.clone()),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let worker = server.spawn_embedding_worker().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while vault.embedding_locality(&id).unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline, "never embedded");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        worker.abort();
        let _ = worker.await;
    });
    runtime.shutdown_background();
    assert_eq!(
        vault.embedding_locality(&id).unwrap(),
        Some(oneiron::embed::EmbedderLocality::ThirdParty)
    );
    assert_eq!(remote.requests().len(), 1);
    assert!(matches!(
        remote_batches(&receipts).as_slice(),
        [(reserved, settled)] if reserved == settled && *reserved > 0
    ));
}

/// A request the run's line cannot cover is refused before it is sent: the
/// rung fails, the reconciler embeds the row on device, and the refusal has
/// its row, with nothing reserved.
#[test]
fn a_remote_batch_its_line_refuses_is_never_sent_and_embeds_on_device() {
    use oneiron::embed::{
        EgressDecision, EgressPredicate, EmbedderLocality, PendingEmbeddingInput,
        PendingEmbeddingReconciler, RemoteRung,
    };
    use oneiron::llm::run_admission::{MemoryReceipts, RunDenied, RunEvent};
    struct Leaves;
    impl EgressPredicate for Leaves {
        fn decide(&self, _: &PendingEmbeddingInput) -> EgressDecision {
            EgressDecision::Allow
        }
    }
    let local = MockEndpoint::start(MockBehaviour::Ok);
    let remote = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().unwrap();
    let vault = test_vault(dir.path());
    let id = put_claim(&vault, 0x95, "a row its line cannot pay for");
    let config = endpoint_config(&local.base);
    let section = remote_section(&remote.base, id);
    let receipts = Arc::new(MemoryReceipts::default());
    let rung = endpoint::HttpEmbedder::from_config(&section.endpoint_config(&config)).unwrap();
    rung.pay_through(Arc::new(
        super::admitted::AdmittedRequests::on_line(
            &section,
            EmbedderLocality::ThirdParty,
            receipts.clone(),
            1,
        )
        .unwrap(),
    ));
    let primary = endpoint::HttpEmbedder::from_config(&config).unwrap();
    let reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), primary)
        .with_remote_rung(RemoteRung::new(rung, Arc::new(Leaves)))
        .unwrap();
    let report = reconciler.reconcile_once().unwrap();
    assert!(report.remote_failed_fallback_local >= 1);
    assert!(remote.requests().is_empty(), "a refused batch went out");
    assert_eq!(
        vault.embedding_locality(&id).unwrap(),
        Some(EmbedderLocality::OnDevice)
    );
    let rows = receipts.rows();
    assert!(
        matches!(
            rows.as_slice(),
            [row] if matches!(row.event, RunEvent::Denied { reason: RunDenied::Budget { .. }, .. })
        ),
        "{rows:?}"
    );
}

/// Sol R1 on A2 (F2, F3): each request a paid remote sends is its own paid
/// call, and an embed whose listing fails sends no request and is charged
/// nothing. Two 20 KiB texts on the Oneiron wire go out as two requests.
#[test]
fn each_request_a_paid_remote_sends_is_its_own_paid_call() {
    use oneiron::embed::{
        Embedder as _, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
    };
    use oneiron::llm::run_admission::MemoryReceipts;
    let remote = MockEndpoint::start(MockBehaviour::ListingDown);
    let config = endpoint_config("http://127.0.0.1:1");
    let section = remote_section(&remote.base, oneiron::EntityId::now());
    let receipts = Arc::new(MemoryReceipts::default());
    let http = endpoint::HttpEmbedder::from_config(&section.endpoint_config(&config)).unwrap();
    http.hold_as_rung(Arc::new(Mutex::new(super::remote::RungHold {
        transform: Some(MOCK_TRANSFORM.to_owned()),
        measured: false,
    })));
    http.pay_through(Arc::new(
        super::admitted::AdmittedRequests::unmetered(
            &section,
            EmbedderLocality::ThirdParty,
            receipts.clone(),
        )
        .unwrap(),
    ));
    let inputs: Vec<PendingEmbeddingInput> = (0..2)
        .map(|_| PendingEmbeddingInput {
            entity_id: oneiron::EntityId::now(),
            payload: PendingEmbeddingPayload::TurnText("long turn ".repeat(2 * 1024)),
            pending_embedding_token: Vec::new(),
        })
        .collect();
    assert!(http.embed(&inputs).is_err(), "the listing is down");
    assert!(remote.requests().is_empty());
    assert!(receipts.rows().is_empty(), "{:?}", receipts.rows());
    remote.set_behaviour(MockBehaviour::OneironWire);
    assert_eq!(http.embed(&inputs).unwrap().len(), 2);
    assert_eq!(remote.requests().len(), 2);
    let paid = remote_batches(&receipts);
    assert!(
        matches!(paid.as_slice(), [(a, b), (c, d)] if a == b && c == d && *a > 20 * 1024),
        "{paid:?}"
    );
}

/// Sol R1 on A2 (F1): the startup probe of a remote rung embeds a text at
/// the remote, so it is a paid call too, with its rows.
#[test]
fn the_startup_probe_of_a_remote_rung_is_a_paid_call() {
    use oneiron::llm::run_admission::MemoryReceipts;
    let local = MockEndpoint::start(MockBehaviour::Ok);
    let remote = MockEndpoint::start(MockBehaviour::Ok);
    let mut config = endpoint_config(&local.base);
    config.remote = Some(remote_section(&remote.base, oneiron::EntityId::now()));
    let receipts = Arc::new(MemoryReceipts::default());
    assert!(
        build_slot(Some(&config), receipts.clone())
            .unwrap()
            .is_some()
    );
    assert_eq!(remote.requests().len(), 1, "one probe post at the remote");
    assert!(matches!(
        remote_batches(&receipts).as_slice(),
        [(reserved, settled)] if reserved == settled
    ));
}

#[test]
fn remote_endpoint_init_config_drives_egress_and_semantic_queries_without_manual_edits() {
    use crate::config::EmbedderLocality;
    let local = MockEndpoint::start(MockBehaviour::Ok);
    let remote = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    let mut bytes = [0xA9; 16];
    bytes[0] = 0x7e;
    let id = oneiron::EntityId::from_bytes(bytes).unwrap();
    crate::commands::init(crate::cli::InitArgs {
        path: dir.path().join("vault"),
        config: Some(config_path.clone()),
        embedder: Some(EmbedderProvider::Endpoint),
        embedder_endpoint: Some(remote.base.clone()),
        embedder_locality: Some(EmbedderLocality::ThirdParty),
        embedder_fallback_endpoint: Some(local.base.clone()),
        embedder_egress_allow: vec![id.to_hex()],
        embedder_model_id: Some("test/model@rev".into()),
        embedder_model_key: Some(MODEL_KEY.into()),
        dimensions: Some(DIMS),
        map_size: 64 * 1024 * 1024,
        ..Default::default()
    })
    .unwrap();
    let config = crate::config::resolve_serve_config_with_sources(
        &crate::config::ServeArgs {
            config: Some(config_path),
            ..Default::default()
        },
        crate::config::EnvConfig::default(),
        None,
    )
    .unwrap();
    let vault =
        Arc::new(oneiron::Vault::open_owned(&config.vault_path, config.vault_config()).unwrap());
    let seeded = vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .unwrap()
        .len();
    let allowed = put_claim(&vault, 0xA9, "remote onboarding claim");
    assert_eq!(allowed, id);
    let unknown = put_claim(&vault, 0xAA, "keep this claim on device");
    let embedder = config.embedder.as_ref().unwrap();
    let slot = EmbedderSlot::from_config(embedder).unwrap().unwrap();
    let reconciler = oneiron::embed::PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        slot.ensure_ready(|_| Ok(())).unwrap() as Arc<dyn oneiron::embed::Embedder>,
    )
    .with_remote_rung(slot.remote_rung(receipts()).unwrap().unwrap())
    .unwrap();
    let report = reconciler.reconcile_once().unwrap();
    assert_eq!(
        (
            report.routed_remote,
            report.egress_no_verdict,
            report.filled
        ),
        (1, 1 + seeded, 2 + seeded)
    );
    assert_eq!(
        vault.embedding_locality(&id).unwrap(),
        Some(oneiron::embed::EmbedderLocality::ThirdParty)
    );
    assert_eq!(
        vault.embedding_locality(&unknown).unwrap(),
        Some(oneiron::embed::EmbedderLocality::OnDevice)
    );
    let query = slot.embed_query("remote onboarding claim").unwrap();
    let hits = vault.search_vector(&query, 2 + seeded).unwrap();
    assert!(hits.iter().any(|hit| hit.id == id));
}

#[test]
fn busy_embedding_worker_publishes_due_staged_revisions_between_passes() {
    let mock = MockEndpoint::start(MockBehaviour::Ok);
    let dir = tempfile::tempdir().unwrap();
    let vault = test_vault(dir.path());
    let mut config = endpoint_config(&mock.base);
    config.batch_size = 1;
    let slot = EmbedderSlot::from_config(&config).unwrap().unwrap();
    slot.ensure_ready(|_| Ok(())).unwrap();
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let document = oneiron::EntityId::now();
    let vector = mock_vector("staged revision", DIMS);
    for content in ["original indexed text", "staged revised text"] {
        let body = rmp_serde::to_vec_named(&json!({"content": content})).unwrap();
        vault
            .batch()
            .put(
                &document,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .text(&document, &[("content", content)])
            .vector(&document, &vector)
            .commit()
            .unwrap();
    }
    let expected = vault.pin_entity_revision(&document).unwrap();
    assert_ne!(vault.indexed_revision(&document).unwrap(), Some(expected));
    let backlog = [
        put_claim(&vault, 0xD1, "first pending"),
        put_claim(&vault, 0xD2, "second pending"),
    ];
    let pause = Arc::new(EmbeddingPause {
        request: mock.requests().len() + 2,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    *mock.state.pause.lock().unwrap() = Some(pause.clone());
    let server = Arc::new(
        crate::server::SyncServer::new(vault.clone(), Default::default())
            .unwrap()
            .with_embedder(Some(slot)),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let worker = server.spawn_embedding_worker().unwrap();
        let paused =
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified())
                .await;
        // Read the public result while the second leased request is paused.
        let indexed = vault.indexed_revision(&document).unwrap();
        let pending = backlog
            .iter()
            .any(|id| vault.get_vector(id).unwrap().is_none());
        pause.release.notify_one();
        worker.abort();
        let _ = worker.await;
        assert!(paused.is_ok(), "worker must reach its second nonempty pass");
        assert!(pending, "the global queue was not empty at publication");
        assert_eq!(indexed, Some(expected));
    });
    runtime.shutdown_background();
}

/// Wave 9 long-context A/B: the recall verb ran `RecallExecution::default()`,
/// so a vault served with an embedder still recalled sparse, and a paraphrase
/// that shares no word with its memory found nothing. Both server doors, the
/// HTTP facade and the WebSocket read RPC, now embed the query, so a claim
/// written through the facade is found by a paraphrase.
#[test]
fn recall_doors_embed_the_query_when_the_vault_has_an_embedder() {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    const SECRET: &str = "embedder-recall-secret";
    let mock = MockEndpoint::start(MockBehaviour::Concepts);
    let dir = tempfile::tempdir().unwrap();
    let vault = test_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let config = EmbedderConfig {
        idle_interval_ms: 20,
        ..endpoint_config(&mock.base)
    };
    let slot = EmbedderSlot::from_config(&config).unwrap().unwrap();
    let server = Arc::new(
        crate::server::SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_embedder(Some(slot)),
    );
    let recipe = format!(
        "scope=core:read,core:write;principal_ref={};actor_class=human",
        owner.to_hex()
    );
    let (slip, key) = crate::test_credentials::credential(&server, &recipe);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let worker = server.spawn_embedding_worker().unwrap();
        let post = |verb: &str, payload: Value| {
            let request = crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &key,
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            );
            let app = crate::build_app(Arc::clone(&server));
            async move {
                let response = app.oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
                serde_json::from_slice::<Value>(&bytes).unwrap()
            }
        };
        // The target is the oldest claim. With no vector channel, recall
        // falls back to recency and the newer decoys fill every slot.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut claimed = Vec::new();
        for (hour, value) in [
            "The mechanic says the automobile needs new brakes.",
            "The quarterly report is due on the fifth.",
            "Remember to water the basil on the balcony.",
            "The flight to Lisbon boards at gate twelve.",
            "Our team retro covered flaky integration tests.",
            "The library closes early on Sundays.",
            "Pack the blue umbrella for the trip.",
            "The piano tuner visits in spring.",
            "Renew the passport before October.",
        ]
        .into_iter()
        .enumerate()
        {
            let at = now - 3_600 * (10 - hour as u64);
            let receipt = post(
                "claim_upsert",
                json!({"predicate": format!("note.n{hour}"), "subject_ref": owner.to_hex(),
                    "value": value, "confidence": 0.9, "source": "user_stated",
                    "occurred_at": at, "learned_at": at}),
            )
            .await;
            claimed.push(receipt["claim_short_id"].as_str().unwrap().to_owned());
        }
        let target = claimed[0].clone();

        let found = |pack: &Value| -> (Value, bool) {
            let mut ids = pack["items"].as_array().into_iter().flatten();
            (
                pack["retrieval_meta"]["sparse"].clone(),
                ids.any(|item| item["short_id"].as_str() == Some(target.as_str())),
            )
        };
        // Wait until the claim vectors are filled and the HTTP door answers.
        let request = json!({"query": "car repair garage", "limit": 3});
        let mut http = Value::Null;
        for _ in 0..600 {
            http = post("recall", request.clone()).await;
            if found(&http).1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(found(&http), (json!(false), true), "{target}: {http}");

        let auth = crate::test_credentials::authenticate(&server, &recipe);
        let frames = crate::livequery::bound_rpc(
            &server,
            &auth,
            crate::livequery::RpcRequest {
                request_id: 9,
                method: "recall".to_owned(),
                params: request,
            },
        )
        .unwrap();
        let ws = crate::livequery::test_wire::reply(&frames);
        assert_eq!(found(&ws["result"]), (json!(false), true), "{target}: {ws}");
        worker.abort();
    });
    runtime.shutdown_background();
}

mod turns;
