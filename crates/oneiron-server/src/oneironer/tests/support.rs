//! A stub tagger server inside the test process, and the vaults and servers
//! the slot's tests share. Every text here is fixture text written for these
//! tests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

use crate::config::{OneironerConfig, OneironerMode, OneironerProvider, SyncServerConfig};
use crate::server::SyncServer;

pub(super) const CHECKPOINT: &str = "0123456789abcdef";
pub(super) const LABEL_COUNT: u32 = 3;
pub(super) const NOW: u64 = 1_790_000_000;
const ROOM: &str = "71717171717171717171717171717171";

/// What the stub answers to `POST /v1/extract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Answer {
    /// One span over the first word of the first message, one link-free mood.
    Good,
    /// HTTP 500 whose body echoes the request.
    ServerError,
    /// A valid answer, sent after the client's timeout.
    Slow,
    /// A span that runs past its message.
    BadOffsets,
    /// HTTP 200 whose body is not the contract and echoes the request.
    NotTheContract,
    /// A status line no registry names, as a number the stub picked.
    NonstandardStatus,
}

/// The unregistered status the stub answers with.
pub(super) const NONSTANDARD_STATUS: u16 = 447;

pub(super) struct StubState {
    answer: Mutex<Answer>,
    card: Mutex<Value>,
    extracts: Mutex<Vec<Value>>,
    /// The extract, counted from one, at which the stub starts serving this
    /// card: that call is the first one the other model answers.
    swap: Mutex<Option<(usize, Value)>>,
    /// A status `GET /v1/model` answers with instead of the card.
    card_status: Mutex<Option<u16>>,
    /// How many of the next `GET /v1/model` answers break off mid-body.
    card_breaks: Mutex<usize>,
    /// How many card answers broke off.
    card_broken: Mutex<usize>,
}

pub(super) struct StubTagger {
    pub(super) base: String,
    pub(super) state: Arc<StubState>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for StubTagger {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

pub(super) fn card(checkpoint: &str) -> Value {
    json!({
        "checkpoint_sha16": checkpoint,
        "contract_version": crate::oneironer::endpoint::CONTRACT_VERSION,
        "label_count": LABEL_COUNT,
        "returns": {"spans": true, "links": true, "mood": true},
        "engine": "stub"
    })
}

impl StubTagger {
    pub(super) fn start(answer: Answer) -> Self {
        let state = Arc::new(StubState {
            answer: Mutex::new(answer),
            card: Mutex::new(card(CHECKPOINT)),
            extracts: Mutex::new(Vec::new()),
            swap: Mutex::new(None),
            card_status: Mutex::new(None),
            card_breaks: Mutex::new(0),
            card_broken: Mutex::new(0),
        });
        let app = Router::new()
            .route("/v1/model", get(stub_model))
            .route("/v1/extract", post(stub_extract))
            .with_state(Arc::clone(&state));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("stub runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("stub listener");
        let addr: SocketAddr = listener.local_addr().expect("stub addr");
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}"),
            state,
            runtime: Some(runtime),
        }
    }

    pub(super) fn set_answer(&self, answer: Answer) {
        *self.state.answer.lock().expect("answer lock") = answer;
    }

    pub(super) fn set_card(&self, card: Value) {
        *self.state.card.lock().expect("card lock") = card;
    }

    /// `GET /v1/model` answers with this status and no card.
    pub(super) fn set_card_status(&self, status: u16) {
        *self.state.card_status.lock().expect("card status lock") = Some(status);
    }

    /// The next `count` card answers send part of the card, then the
    /// connection drops before the body ends.
    pub(super) fn break_card_bodies(&self, count: usize) {
        *self.state.card_breaks.lock().expect("card breaks lock") = count;
    }

    /// How many card answers broke off so far.
    pub(super) fn card_bodies_broken(&self) -> usize {
        *self.state.card_broken.lock().expect("card broken lock")
    }

    /// From its `nth` extract on, the stub is another model serving `card`.
    pub(super) fn swap_card_at_extract(&self, nth: usize, card: Value) {
        *self.state.swap.lock().expect("swap lock") = Some((nth, card));
    }

    /// Every `POST /v1/extract` body the stub received.
    pub(super) fn extracts(&self) -> Vec<Value> {
        self.state.extracts.lock().expect("extracts lock").clone()
    }

    pub(super) fn config(&self) -> OneironerConfig {
        endpoint_config(&self.base)
    }
}

async fn stub_model(State(state): State<Arc<StubState>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let status = *state.card_status.lock().expect("card status lock");
    if let Some(status) = status {
        return StatusCode::from_u16(status)
            .expect("stub status")
            .into_response();
    }
    let card = state.card.lock().expect("card lock").clone();
    let breaks = {
        let mut breaks = state.card_breaks.lock().expect("card breaks lock");
        let now = *breaks > 0;
        *breaks = breaks.saturating_sub(1);
        now
    };
    if breaks {
        *state.card_broken.lock().expect("card broken lock") += 1;
        // The headers and half the card, flushed while the stream waits,
        // then a stream error: the server drops the connection before the
        // chunked body ends, so the client's body read breaks off.
        let bytes = serde_json::to_vec(&card).expect("card bytes");
        let half = axum::body::Bytes::copy_from_slice(&bytes[..bytes.len() / 2]);
        let body = futures_util::stream::unfold(0_u8, move |step| {
            let half = half.clone();
            async move {
                match step {
                    0 => Some((Ok(half), 1)),
                    1 => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Some((Err(std::io::Error::other("stub card body broke off")), 2))
                    }
                    _ => None,
                }
            }
        });
        return axum::response::Response::builder()
            .header("content-type", "application/json")
            .body(axum::body::Body::from_stream(body))
            .expect("broken card response");
    }
    axum::Json(card).into_response()
}

async fn stub_extract(
    State(state): State<Arc<StubState>>,
    axum::Json(body): axum::Json<Value>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;
    let received = {
        let mut extracts = state.extracts.lock().expect("extracts lock");
        extracts.push(body.clone());
        extracts.len()
    };
    let swap = state.swap.lock().expect("swap lock").clone();
    if let Some((_, swapped)) = swap.filter(|(nth, _)| *nth == received) {
        *state.card.lock().expect("card lock") = swapped;
    }
    let answer = *state.answer.lock().expect("answer lock");
    let first = body["messages"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let word = first.find(' ').unwrap_or(first.len());
    let output = |end: usize| {
        json!({
            "spans": [{"message": 0, "start": 0, "end": end, "label": "PERSON", "confidence": 0.9}],
            "links": [],
            "vad": {"valence": 0.1, "arousal": 0.5, "dominance": 0.5}
        })
    };
    match answer {
        Answer::Good => Ok(axum::Json(output(word)).into_response()),
        Answer::BadOffsets => Ok(axum::Json(output(first.len() + 7)).into_response()),
        Answer::Slow => {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            Ok(axum::Json(output(word)).into_response())
        }
        Answer::ServerError => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("refused: {first}"),
        )
            .into_response()),
        Answer::NotTheContract => Ok(format!("{{\"echo\": \"{first}\"").into_response()),
        Answer::NonstandardStatus => Ok(StatusCode::from_u16(NONSTANDARD_STATUS)
            .expect("stub status")
            .into_response()),
    }
}

/// An endpoint section in shadow mode, with a short timeout and no retry
/// backoff so a test can watch every attempt.
pub(super) fn endpoint_config(base: &str) -> OneironerConfig {
    OneironerConfig {
        provider: OneironerProvider::Endpoint,
        mode: OneironerMode::Shadow,
        url: Some(base.to_owned()),
        checkpoint_sha16: Some(CHECKPOINT.to_owned()),
        label_count: Some(LABEL_COUNT),
        labels: [("PERSON".to_owned(), "PERSON".to_owned())].into(),
        timeout_ms: 500,
        idle_interval_ms: 1_000,
        retry_backoff_secs: 0,
        max_retry_backoff_secs: 0,
        ..OneironerConfig::default()
    }
}

/// A vault; on a pinned clock two vaults given the same writes store the same
/// ids. Armed, every witness commits a tagging marker.
pub(super) fn open_vault(path: &std::path::Path, armed: bool, pinned: bool) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    if pinned {
        config.store_clock = oneiron::store::ports::ManualClock::new(NOW).bundle();
    }
    if armed {
        config.tagging =
            Some(oneiron::tagging::TaggingMarkerConfig::new(CHECKPOINT).expect("checkpoint"));
    }
    Arc::new(Vault::open(path, config).expect("open vault"))
}

/// Copies a closed vault's files, so two vaults start from the same bytes.
pub(super) fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).expect("read vault dir") {
        let entry = entry.expect("vault dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            std::fs::create_dir_all(&target).expect("create dir");
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy vault file");
        }
    }
}

pub(super) fn server(vault: &Arc<Vault>, tagger: Option<&OneironerConfig>) -> Arc<SyncServer> {
    let slot = super::super::build_slot(tagger).expect("tagger slot");
    Arc::new(
        SyncServer::new(
            Arc::clone(vault),
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server")
        .with_tagger(slot),
    )
}

pub(super) fn speaker(vault: &Vault) -> EntityId {
    let id = EntityId::from_bytes([0x21; 16]).expect("speaker id");
    if vault.get(&id).expect("speaker read").is_none() {
        vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({"name": "fixture speaker"}))
                    .expect("speaker body"),
            )
            .expect("speaker");
    }
    id
}

/// Witnesses one fresh turn through the engine's witness door, the door the
/// `/v1/core/facade/witness` route calls, and returns the turn id.
pub(super) fn witness(vault: &Vault, content: &str) -> EntityId {
    let receipt = vault
        .memory(speaker(vault), EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: ROOM.into(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: content.into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: NOW,
        })
        .expect("witness");
    EntityId::from_hex(receipt.receipt_ref.trim_start_matches("witness:")).expect("turn id")
}

pub(super) fn markers(vault: &Vault) -> Vec<oneiron::attempt_queue::AttemptRecord> {
    oneiron::attempt_queue::AttemptQueue::new(vault)
        .list()
        .expect("attempt rows")
        .into_iter()
        .filter(|record| record.kind == oneiron::tagging::TAGGING_MARKER_KIND)
        .collect()
}

/// Waits (on real time) until `done` holds, up to ten seconds.
pub(super) fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    done()
}
