//! A stand-in embedder on loopback: the plain OpenAI `/v1/embeddings` wire,
//! answering bag-of-words vectors.
//!
//! A text's vector is the normalised sum of one fixed pseudo-random vector per
//! word, so texts that share words land near each other and the vector index
//! sees clustered data rather than noise. It is a load device, not a model: it
//! stands in for a shared embedder outside the vault process, which is how the
//! vault's own vector work is measured without a model run.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use super::corpus::{Rng, tag_index};

pub(super) const MODEL_KEY: &str = "bench-bag-of-words";
pub(super) const MODEL_ID: &str = "bench/bag-of-words@v1";

#[derive(Clone)]
struct Stub {
    dimensions: usize,
    embedded: Arc<AtomicU64>,
    records: Arc<Mutex<HashSet<usize>>>,
}

/// The running stub: its address, how many inputs it has embedded, and which
/// records' tagged texts were among them.
pub(super) struct StubEmbedder {
    addr: SocketAddr,
    embedded: Arc<AtomicU64>,
    records: Arc<Mutex<HashSet<usize>>>,
    _runtime: tokio::runtime::Runtime,
}

impl StubEmbedder {
    pub(super) fn start(dimensions: usize) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("stub embedder runtime: {e}"))?;
        let embedded = Arc::new(AtomicU64::new(0));
        let records = Arc::new(Mutex::new(HashSet::new()));
        let stub = Stub {
            dimensions,
            embedded: Arc::clone(&embedded),
            records: Arc::clone(&records),
        };
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .map_err(|e| format!("stub embedder bind: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("stub embedder address: {e}"))?;
        let app = Router::new()
            .route("/v1/models", get(models))
            .route("/v1/embeddings", post(embeddings))
            .with_state(stub);
        runtime.spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            addr,
            embedded,
            records,
            _runtime: runtime,
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    /// Every input embedded: corpus texts, probes and retries alike.
    pub(super) fn embedded(&self) -> u64 {
        self.embedded.load(Ordering::Relaxed)
    }

    /// How many distinct records had a text carrying their tag embedded.
    pub(super) fn records(&self) -> usize {
        self.records.lock().map_or(0, |seen| seen.len())
    }
}

async fn models() -> Json<Value> {
    Json(json!({"object": "list", "data": [{"id": MODEL_KEY, "object": "model"}]}))
}

async fn embeddings(State(stub): State<Stub>, Json(request): Json<Value>) -> Json<Value> {
    let inputs = match &request["input"] {
        Value::Array(items) => items.iter().map(|v| v.as_str().unwrap_or("")).collect(),
        Value::String(one) => vec![one.as_str()],
        _ => Vec::new(),
    };
    let data = inputs
        .iter()
        .enumerate()
        .map(|(index, text)| json!({"object": "embedding", "index": index, "embedding": vector(text, stub.dimensions)}))
        .collect::<Vec<_>>();
    // Counted once the vectors exist, just before they are answered.
    stub.embedded
        .fetch_add(inputs.len() as u64, Ordering::Relaxed);
    if let Ok(mut seen) = stub.records.lock() {
        seen.extend(inputs.iter().filter_map(|text| tag_index(text)));
    }
    Json(json!({"object": "list", "model": MODEL_KEY, "data": data}))
}

/// The normalised sum of each word's fixed vector; a text with no words gets
/// one fixed vector so it still answers with a nonzero norm.
fn vector(text: &str, dimensions: usize) -> Vec<f32> {
    let mut sum = vec![0f32; dimensions];
    let mut words = 0;
    for token in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        words += 1;
        let mut rng = Rng::new(fnv1a(&token.to_lowercase()));
        for slot in &mut sum {
            *slot += (rng.unit() * 2.0 - 1.0) as f32;
        }
    }
    if words == 0 {
        sum[0] = 1.0;
    }
    let norm = sum
        .iter()
        .map(|x| x * x)
        .sum::<f32>()
        .sqrt()
        .max(f32::MIN_POSITIVE);
    sum.iter().map(|x| x / norm).collect()
}

fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}
