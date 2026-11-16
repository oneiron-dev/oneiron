#![cfg(oneiron_test_support)]
//! Census L1-27 (ARCH-0053 `#embedding-admission-built`): a served vault's
//! background embeddings pay from the vault's background line, built from
//! the vault's budget policy as the Dreamer pass's line is. A `budget_policy`
//! row that caps the vault's system principal caps the remote rung's
//! batches in total: a batch past the cap is never sent, its row embeds on
//! device, and the refusal's receipt names the line. With no such row,
//! every batch goes out as before.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! background_embedding_line`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use oneiron::embed::EmbedderLocality;
use oneiron::llm::run_admission::{MemoryReceipts, RunDenied, RunEvent, RunReceipt};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::config::remote_embedder::{EgressPolicy, RemoteEmbedderConfig};
use oneiron_server::config::{
    EmbedderConfig, EmbedderProvider, EndpointEmbedderConfig, ServeConfig, SyncServerConfig,
};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::background_embedding::{
    spawn_embedding_worker, with_served_embedder,
};
use rmpv::Value;
use serde_json::{Value as Json, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The width of the vault and of both mock endpoints' vectors.
const DIMS: usize = 8;
/// The model the vault and both endpoints embed with.
const MODEL_ID: &str = "test/model@rev";
/// The key both endpoints list and are called with.
const MODEL_KEY: &str = "test-embedding-model";
/// The bytes of each row's text: one row's batch fits under [`CAP_TOKENS`],
/// a second row's does not.
const ROW_TEXT_BYTES: usize = 1_000;
/// The cap the policy row puts on the vault's system principal, in tokens:
/// above one batch's reservation (each text's bytes plus its special
/// tokens), below two batches'.
const CAP_TOKENS: u64 = 1_500;
/// The run name each request on the vault's background line is admitted
/// under, before `:` and the request's id.
const BACKGROUND_LINE: &str = "background-embedding";

/// An OpenAI-wire embedding endpoint on loopback that lists [`MODEL_KEY`]
/// and answers each text with a one-hot vector, counting its embedding
/// posts.
struct MockEndpoint {
    base: String,
    posts: Arc<Mutex<usize>>,
    // Dropping the runtime stops the server; the field keeps it alive for
    // the length of the test.
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
        let posts = Arc::new(Mutex::new(0_usize));
        let app = Router::new()
            .route("/v1/models", get(mock_models))
            .route("/v1/embeddings", post(mock_embeddings))
            .with_state(Arc::clone(&posts));
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
            posts,
            runtime: Some(runtime),
        })
    }

    /// The embedding requests the endpoint has answered so far.
    fn posts(&self) -> usize {
        *self
            .posts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

async fn mock_models() -> axum::Json<Json> {
    axum::Json(json!({ "data": [{ "id": MODEL_KEY }] }))
}

async fn mock_embeddings(
    State(posts): State<Arc<Mutex<usize>>>,
    axum::Json(body): axum::Json<Json>,
) -> axum::Json<Json> {
    *posts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
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

/// A CLAIM body with the full v2 scope stamp the raw write door asks for,
/// its value `text`.
fn claim_body(text: &str) -> TestResult<Vec<u8>> {
    let subject = EntityId::from_bytes([0x7d; 16])?;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("pred"), Value::from("test.status")),
            (
                Value::from("subj"),
                Value::Binary(subject.as_bytes().to_vec()),
            ),
            (Value::from("val"), Value::from(text)),
            (Value::from("conf"), Value::F32(0.9)),
            (Value::from("confBand"), Value::from("certain")),
            (
                Value::from("confBasis"),
                Value::from("deterministic_fallback"),
            ),
            (Value::from("appr"), Value::from("auto")),
            (Value::from("life"), Value::from("active")),
            (
                Value::from("worldId"),
                Value::Binary(oneiron::claim::base_world_id().as_bytes().to_vec()),
            ),
            (Value::from("scopeRelationshipId"), Value::from("all")),
            (
                Value::from("scopeFacetId"),
                Value::Binary(
                    oneiron::claim::substrate_facet_id(subject)?
                        .as_bytes()
                        .to_vec(),
                ),
            ),
            (
                Value::from("scopeProjectId"),
                Value::Binary(oneiron::claim::default_project_id().as_bytes().to_vec()),
            ),
            (Value::from("scopeVersion"), Value::from(2_u64)),
        ]),
    )?;
    Ok(body)
}

/// The id of the row `seed` names.
fn row_id(seed: u8) -> TestResult<EntityId> {
    let mut bytes = [seed; 16];
    bytes[0] = 0x7e;
    Ok(EntityId::from_bytes(bytes)?)
}

/// Puts the CLAIM row `id`, its text [`ROW_TEXT_BYTES`] long, pending its
/// vector.
fn put_row(vault: &Vault, id: EntityId, seed: u8) -> TestResult {
    let text: String = std::iter::repeat_n(char::from(b'a' + seed % 26), ROW_TEXT_BYTES).collect();
    vault
        .batch()
        .put(
            &id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::temporal::TimeRange { start: 1, end: 1 },
            1,
            &claim_body(&text)?,
        )
        .commit()?;
    Ok(())
}

/// A policy pack whose one `budget_policy` row caps `principal` at
/// [`CAP_TOKENS`].
fn cap_manifest(principal: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (
            Value::from("pack_id"),
            Value::from("background-embedding-cap"),
        ),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("self.memory.")),
                (Value::from("axes"), axes()),
            ])]),
        ),
        (
            Value::from("budget_policy"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor"), Value::from(principal.to_hex())),
                (Value::from("cap"), Value::from(CAP_TOKENS)),
            ])]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)?;
    Ok(data)
}

/// The served embedder: `primary` on this device, and `remote` as a
/// third-party rung every row in `rows` may leave for.
fn serve_config(primary: &MockEndpoint, remote: &MockEndpoint, rows: &[EntityId]) -> ServeConfig {
    let embedder = EmbedderConfig {
        provider: EmbedderProvider::Endpoint,
        dimensions: DIMS,
        model_id: MODEL_ID.to_owned(),
        batch_size: 1,
        idle_interval_ms: 20,
        endpoint: EndpointEmbedderConfig {
            endpoint: Some(primary.base.clone()),
            model_key: Some(MODEL_KEY.to_owned()),
            ..EndpointEmbedderConfig::default()
        },
        remote: Some(RemoteEmbedderConfig {
            endpoint: remote.base.clone(),
            model_key: MODEL_KEY.to_owned(),
            locality: oneiron_server::config::EmbedderLocality::ThirdParty,
            artifact: None,
            api_key_env: None,
            key_secret: None,
            lease_ms: 120_000,
            timeout_ms: 1_000,
            egress: Some(EgressPolicy {
                allow: rows.iter().map(EntityId::to_hex).collect(),
                deny: Vec::new(),
                allow_all: false,
                remote_evidence: None,
            }),
        }),
        ..EmbedderConfig::default()
    };
    ServeConfig {
        embedder: Some(embedder),
        ..ServeConfig::default()
    }
}

/// What one served run saw: where each row's vector was made, in put
/// order, the remote's embedding posts after its startup probe, and every
/// run receipt the worker's requests wrote.
struct Served {
    localities: Vec<Option<EmbedderLocality>>,
    remote_batches: usize,
    receipts: Vec<RunReceipt>,
}

/// Serves `vault` with the embedder [`serve_config`] names, its worker
/// running, and puts the rows one at a time, each after the one before it
/// has its vector.
fn serve_rows(vault: &Arc<Vault>, rows: &[(EntityId, u8)]) -> TestResult<Served> {
    let primary = MockEndpoint::start()?;
    let remote = MockEndpoint::start()?;
    let ids: Vec<EntityId> = rows.iter().map(|(id, _)| *id).collect();
    let config = serve_config(&primary, &remote, &ids);
    let receipts = Arc::new(MemoryReceipts::default());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let served = runtime.block_on(async {
        let server = SyncServer::new(Arc::clone(vault), SyncServerConfig::default())?
            .with_run_receipts(receipts.clone());
        let server = Arc::new(with_served_embedder(server, &config).await?);
        // The startup probes are paid before any vault binds a line.
        let probes = remote.posts();
        let worker = spawn_embedding_worker(&server).ok_or("the served embedder runs no worker")?;
        let mut localities = Vec::new();
        for (id, seed) in rows {
            put_row(vault, *id, *seed)?;
            let deadline = Instant::now() + Duration::from_secs(20);
            let locality = loop {
                if let Some(locality) = vault.embedding_locality(id)? {
                    break locality;
                }
                if Instant::now() > deadline {
                    worker.abort();
                    return Err(format!("row {} was never embedded", id.to_hex()).into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            localities.push(Some(locality));
        }
        worker.abort();
        let _ = worker.await;
        Ok::<_, Box<dyn std::error::Error>>(Served {
            localities,
            remote_batches: remote.posts() - probes,
            receipts: receipts.rows(),
        })
    })?;
    runtime.shutdown_background();
    Ok(served)
}

fn open_vault(dir: &std::path::Path) -> TestResult<Arc<Vault>> {
    let mut config = VaultConfig::device();
    config.dimensions = DIMS;
    config.embedding_model = Some(MODEL_ID.to_owned());
    Ok(Arc::new(Vault::open(dir, config)?))
}

/// The background line's cap binds the remote rung's batches in total: the
/// first row's batch is paid and sent, the second row's would pass the cap,
/// so it is refused before it is sent and its row embeds on device, and the
/// refusal's receipt names the line. On main every request metered on a
/// line of its own with no limit, so the second batch went out.
#[test]
fn a_background_cap_stops_remote_embedding_and_the_row_embeds_on_device() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let principal = vault.dreamer_authority()?.entity_ref();
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &cap_manifest(principal)?,
    )?;
    let served = serve_rows(&vault, &[(row_id(0x41)?, 0), (row_id(0x42)?, 1)])?;

    let denials: Vec<&RunReceipt> = served
        .receipts
        .iter()
        .filter(|row| matches!(row.event, RunEvent::Denied { .. }))
        .collect();
    println!(
        "localities {:?}, remote batches {}, denials {:?}",
        served.localities,
        served.remote_batches,
        denials
            .iter()
            .map(|row| (row.run.as_str(), &row.event))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        served.localities,
        vec![
            Some(EmbedderLocality::ThirdParty),
            Some(EmbedderLocality::OnDevice)
        ],
        "the first row's batch is paid on the rung, the second embeds on device"
    );
    assert_eq!(served.remote_batches, 1, "the batch past the cap was sent");
    assert!(
        denials.iter().any(|row| {
            row.run.starts_with(&format!("{BACKGROUND_LINE}:"))
                && matches!(
                    row.event,
                    RunEvent::Denied {
                        reason: RunDenied::Budget { .. },
                        ..
                    }
                )
        }),
        "no budget refusal names the background line: {denials:?}"
    );
    Ok(())
}

/// With no cap row, the background line has no limit: every row's batch
/// goes out to the rung, and nothing is refused, as before.
#[test]
fn with_no_cap_row_every_remote_batch_goes_out() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let served = serve_rows(&vault, &[(row_id(0x43)?, 2), (row_id(0x44)?, 3)])?;

    assert_eq!(
        served.localities,
        vec![
            Some(EmbedderLocality::ThirdParty),
            Some(EmbedderLocality::ThirdParty)
        ]
    );
    assert_eq!(served.remote_batches, 2);
    assert!(
        !served
            .receipts
            .iter()
            .any(|row| matches!(row.event, RunEvent::Denied { .. })),
        "a request was refused: {:?}",
        served.receipts
    );
    Ok(())
}
