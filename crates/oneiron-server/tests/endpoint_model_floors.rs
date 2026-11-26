#![cfg(oneiron_test_support)]
//! EMBEDDER-ENDPOINT-VECTOR-FLOORS (FIX-LIST, P1; Engine TASK 26 Nov 22:13, row 3): a vault's
//! vector evidence floors are keyed by its model id whatever the provider. An endpoint section
//! on a shipped model, its queries unprompted, states the model's measured floors (pplx 0.15 /
//! 0.25) before its server is admitted, and an OpenAI-shaped server, which names no run profile,
//! keeps them when the vault admits it. A prompted section, and a model with no measured floors,
//! keep the engine's default (0.30 / 0.50).
//!
//! Red on main (403e2cf7be): an endpoint section states the default before admission, and an
//! admitted server that names no profile sets the default, so both measured assertions fail.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test endpoint_model_floors`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use oneiron::config::VectorEvidenceFloors;
use oneiron::{Vault, VaultConfig};
use oneiron_server::config::embedder::DEFAULT_MODEL_ID;
use oneiron_server::config::{
    EmbedderConfig, EmbedderProvider, EndpointEmbedderConfig, ServeConfig, SyncServerConfig,
};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::background_embedding::with_served_embedder;
use oneiron_server::test_doors::endpoint_model_floors::admit_served_embedder;
use serde_json::{Value as Json, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shipped model's width.
const DIMS: usize = 1024;
/// The key the endpoint lists and is called with.
const MODEL_KEY: &str = "pplx-embed-v1-0.6b";
/// A model with no measured floors.
const UNMEASURED_MODEL_ID: &str = "example/embedder@0000000000000000000000000000000000000000";
/// The shipped model's measured floors (local/model_manager.rs).
const MEASURED: VectorEvidenceFloors = VectorEvidenceFloors {
    floor: 0.15,
    strong: 0.25,
};

/// An OpenAI-wire embedding endpoint on loopback: it lists [`MODEL_KEY`] with no run profile, as
/// every OpenAI-shaped server does, and answers each text with a one-hot vector.
struct MockEndpoint {
    base: String,
    // Dropping the runtime stops the server; the field keeps it alive for the test.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for MockEndpoint {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl MockEndpoint {
    fn start() -> TestResult<Self> {
        let app = Router::new()
            .route("/v1/models", get(mock_models))
            .route("/v1/embeddings", post(mock_embeddings));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        let addr: SocketAddr = listener.local_addr()?;
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            base: format!("http://{addr}/v1"),
            runtime: Some(runtime),
        })
    }
}

async fn mock_models() -> axum::Json<Json> {
    axum::Json(json!({ "data": [{ "id": MODEL_KEY }] }))
}

async fn mock_embeddings(axum::Json(body): axum::Json<Json>) -> axum::Json<Json> {
    let inputs: Vec<String> = match &body["input"] {
        Json::Array(rows) => rows
            .iter()
            .map(|row| row.as_str().unwrap_or_default().to_owned())
            .collect(),
        Json::String(text) => vec![text.clone()],
        _ => Vec::new(),
    };
    let rows: Vec<Json> = inputs
        .iter()
        .enumerate()
        .map(|(index, text)| json!({ "index": index, "embedding": one_hot(text) }))
        .collect();
    axum::Json(json!({ "data": rows }))
}

/// A unit vector on one axis the text picks.
fn one_hot(text: &str) -> Vec<f32> {
    let axis = text.bytes().fold(0_usize, |acc, byte| {
        acc.wrapping_mul(131).wrapping_add(byte.into())
    }) % DIMS;
    let mut vector = vec![0.0_f32; DIMS];
    vector[axis] = 1.0;
    vector
}

/// An endpoint section on `model_id` at `endpoint`, with `query_instruction`.
fn endpoint_section(
    endpoint: &str,
    model_id: &str,
    query_instruction: Option<&str>,
) -> EmbedderConfig {
    EmbedderConfig {
        provider: EmbedderProvider::Endpoint,
        dimensions: DIMS,
        model_id: model_id.to_owned(),
        batch_size: 1,
        idle_interval_ms: 20,
        query_instruction: query_instruction.map(str::to_owned),
        endpoint: EndpointEmbedderConfig {
            endpoint: Some(endpoint.to_owned()),
            model_key: Some(MODEL_KEY.to_owned()),
            ..EndpointEmbedderConfig::default()
        },
        ..EmbedderConfig::default()
    }
}

fn serve_config(embedder: EmbedderConfig) -> ServeConfig {
    ServeConfig {
        embedder: Some(embedder),
        ..ServeConfig::default()
    }
}

/// A vault on the shipped model's space, judged by the engine's default floors until an
/// embedder is admitted.
fn open_vault(dir: &std::path::Path, model_id: &str) -> TestResult<Arc<Vault>> {
    let mut config = VaultConfig::device();
    config.dimensions = DIMS;
    config.embedding_model = Some(model_id.to_owned());
    config.vector_evidence = VectorEvidenceFloors::default();
    Ok(Arc::new(Vault::open(dir, config)?))
}

/// The floors `vault` is judged by once the embedder `section` names has been built as serve
/// builds it (its startup probe answered) and admitted by the vault, as the server's embedding
/// worker admits it.
fn floors_after_admission(
    vault: &Arc<Vault>,
    section: EmbedderConfig,
) -> TestResult<VectorEvidenceFloors> {
    let config = serve_config(section);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let floors = runtime.block_on(async {
        let server = SyncServer::new(Arc::clone(vault), SyncServerConfig::default())?;
        let server = Arc::new(with_served_embedder(server, &config).await?);
        let admitting = Arc::clone(&server);
        tokio::task::spawn_blocking(move || admit_served_embedder(&admitting)).await??;
        Ok::<_, Box<dyn std::error::Error>>(vault.vector_evidence())
    })?;
    runtime.shutdown_background();
    Ok(floors)
}

/// Before any server is admitted, an endpoint section states its model's floors: the shipped
/// model's measured pair when its queries go unprompted, the engine's default for a prompted
/// section and for a model with no measured floors. On main every endpoint section stated the
/// default.
#[test]
fn an_endpoint_section_states_its_models_floors_before_admission() -> TestResult {
    // Never called: the floors are read from the section alone.
    let mock = MockEndpoint::start()?;
    let endpoint = mock.base.as_str();
    let stated = |section: EmbedderConfig| serve_config(section).vault_config().vector_evidence;
    assert_eq!(
        stated(endpoint_section(endpoint, DEFAULT_MODEL_ID, None)),
        MEASURED,
        "the shipped model, unprompted"
    );
    assert_eq!(
        stated(endpoint_section(endpoint, DEFAULT_MODEL_ID, Some(" \n"))),
        MEASURED,
        "an instruction of blanks prompts nothing"
    );
    assert_eq!(
        stated(endpoint_section(endpoint, DEFAULT_MODEL_ID, Some("Represent this query: "))),
        VectorEvidenceFloors::default(),
        "a prompted section: the floors were measured unprompted"
    );
    assert_eq!(
        stated(endpoint_section(endpoint, UNMEASURED_MODEL_ID, None)),
        VectorEvidenceFloors::default(),
        "a model with no measured floors"
    );
    Ok(())
}

/// An OpenAI-shaped server serving the shipped model names no run profile; once the vault admits
/// it, the vault is judged by the model's floors. On main a server that named no profile set
/// the engine's default.
#[test]
fn an_admitted_server_that_names_no_profile_serves_its_models_floors() -> TestResult {
    let mock = MockEndpoint::start()?;
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path(), DEFAULT_MODEL_ID)?;
    assert_eq!(vault.vector_evidence(), VectorEvidenceFloors::default());
    let floors =
        floors_after_admission(&vault, endpoint_section(&mock.base, DEFAULT_MODEL_ID, None))?;
    assert_eq!(floors, MEASURED);
    Ok(())
}

/// The same server, admitted for a prompted section, leaves the vault on the engine's default:
/// the measured floors hold for unprompted queries only.
#[test]
fn an_admitted_server_for_a_prompted_section_keeps_the_default() -> TestResult {
    let mock = MockEndpoint::start()?;
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path(), DEFAULT_MODEL_ID)?;
    let section = endpoint_section(&mock.base, DEFAULT_MODEL_ID, Some("Represent this query: "));
    assert_eq!(floors_after_admission(&vault, section)?, VectorEvidenceFloors::default());
    Ok(())
}
