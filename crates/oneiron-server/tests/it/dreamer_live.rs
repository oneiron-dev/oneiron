// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! The Dreamer on a real model provider (dogfood gate 3, map gap 13): the
//! consolidation-only live acceptance run. Ordinary runs skip it; run it on a
//! host that reaches the provider with
//! `cargo test -p oneiron-server --test it -- --ignored dreamer_live` and:
//!
//! - `ONEIRON_LIVE_BASE_URL`: the provider's OpenAI-compatible origin;
//! - `ONEIRON_LIVE_MODEL`: the model to ask for;
//! - `ONEIRON_LIVE_SERVED`: the model id the provider must say served each
//!   answer. Any other id stops the run, and the server never sees it;
//! - `ONEIRON_LIVE_KEY_FILE`: a file holding the provider key. It is read
//!   here and handed to the server in its environment, never printed;
//! - `ONEIRON_LIVE_OUT`: a directory for the server logs, the receipts and
//!   `report.json`;
//! - `ONEIRON_LIVE_RESPONSE_FORMAT` (optional): the provider's
//!   `response_format`, `schema` (the default) or `none`. Each recorded call
//!   says whether it carried a `response_format`.
//!
//! On invented data it witnesses a short conversation and declares its
//! summary while the server is stopped, so the server queues the work at
//! start (the kill before the queue). Then it:
//! 1. serves with the first model call held at the relay, and kills the
//!    server while it is held (between queue and apply);
//! 2. serves until the passes land, and kills the server (after apply);
//! 3. serves again: a finished pass makes no call;
//! 4. witnesses a user correction in a later conversation and serves until
//!    it is consolidated. Beside it, the owner has stated an instrument, and
//!    a third conversation changes it: a Dreamer correction of the owner's
//!    claim always goes to the verdict role, so that role makes a real call;
//! 5. serves again: the correction holds once.
//!
//! Every model call goes through a relay that forwards it unchanged and keeps
//! the model id each answer names. The server's Admitted, Dispatched and
//! Settled receipts are kept from its log. `report.json` is written whether
//! the run passes or fails.
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::ai_serve::{free_port, oneiron, vault_config, write_config};

/// The provider key's variable in the server's environment.
const KEY_ENV: &str = "ONEIRON_LIVE_PROVIDER_KEY";
/// A quiet spell this long with no call in flight means the passes are done.
const QUIET: Duration = Duration::from_secs(20);
/// The longest one phase waits for the server's model calls.
const PHASE: Duration = Duration::from_secs(600);
/// The provider's request timeout, as the server is configured.
const PROVIDER_TIMEOUT_SECS: u64 = 300;

struct Live {
    origin: String,
    model: String,
    served: String,
    key: String,
    out: PathBuf,
    response_format: String,
}

impl Live {
    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for the live run"))
        };
        let key = std::fs::read_to_string(var("ONEIRON_LIVE_KEY_FILE"))
            .expect("the key file reads")
            .trim()
            .to_owned();
        assert!(!key.is_empty(), "the key file is empty");
        let out = PathBuf::from(var("ONEIRON_LIVE_OUT"));
        std::fs::create_dir_all(&out).unwrap();
        Self {
            origin: var("ONEIRON_LIVE_BASE_URL")
                .trim_end_matches('/')
                .trim_end_matches("/v1")
                .to_owned(),
            model: var("ONEIRON_LIVE_MODEL"),
            served: var("ONEIRON_LIVE_SERVED"),
            key,
            out,
            response_format: std::env::var("ONEIRON_LIVE_RESPONSE_FORMAT")
                .unwrap_or_else(|_| "schema".to_owned()),
        }
    }
}

/// One call the relay forwarded, as the report keeps it.
#[derive(Clone, serde::Serialize)]
struct Call {
    phase: String,
    system: String,
    input: String,
    status: u16,
    /// Whether the request carried a `response_format`.
    response_format: bool,
    /// The models the answer named. A name other than the expected one is
    /// kept as `ANOTHER_MODEL`: the provider chose its words.
    served: Vec<String>,
    /// The assistant text of the answer's first choice, the one the server
    /// reads. Nothing else of the provider's body is kept, so no provider
    /// diagnostic can carry the key into the report.
    content: String,
    answer_bytes: usize,
}

/// What the report keeps for a model name other than the expected one.
const ANOTHER_MODEL: &str = "(another model)";

/// Forwards the server's model calls to the provider unchanged. It holds a
/// call instead when asked to, and refuses an answer another model served.
struct Relay {
    origin: String,
    served: String,
    /// Cut out of every answer the relay keeps.
    key: String,
    client: reqwest::Client,
    phase: Mutex<String>,
    hold: AtomicBool,
    holding: Notify,
    in_flight: AtomicUsize,
    calls: Mutex<Vec<Call>>,
    wrong_model: AtomicBool,
}

impl Relay {
    async fn start(live: &Live) -> (Arc<Self>, String) {
        let relay = Arc::new(Self {
            origin: live.origin.clone(),
            served: live.served.clone(),
            key: live.key.clone(),
            client: no_redirects(),
            phase: Mutex::new(String::new()),
            hold: AtomicBool::new(false),
            holding: Notify::new(),
            in_flight: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            wrong_model: AtomicBool::new(false),
        });
        let app = Router::new()
            .route("/v1/chat/completions", post(forward))
            .with_state(Arc::clone(&relay));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (relay, url)
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn enter(&self, phase: &str) {
        *self.phase.lock().unwrap() = phase.to_owned();
    }

    /// Waits for `calls` forwarded calls, then for a quiet spell.
    async fn settle(&self, calls: usize) {
        let started = Instant::now();
        while self.calls().len() < calls {
            assert!(started.elapsed() < PHASE, "the server made too few calls");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let mut heard = (self.calls().len(), Instant::now());
        loop {
            assert!(started.elapsed() < PHASE, "the server never went quiet");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = self.calls().len();
            if now != heard.0 || self.in_flight.load(Ordering::SeqCst) > 0 {
                heard = (now, Instant::now());
            } else if heard.1.elapsed() >= QUIET {
                return;
            }
        }
    }
}

async fn forward(
    State(relay): State<Arc<Relay>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if relay.hold.swap(false, Ordering::SeqCst) {
        relay.holding.notify_one();
        // Never sent upstream: the server is killed while it waits.
        std::future::pending::<()>().await;
    }
    relay.in_flight.fetch_add(1, Ordering::SeqCst);
    let mut request = relay
        .client
        .post(format!("{}{}", relay.origin, uri.path()))
        .body(body.clone());
    for name in ["authorization", "content-type", "accept"] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value);
        }
    }
    let (status, kind, answer) = match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let kind = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/json")
                .to_owned();
            (status, kind, response.bytes().await.unwrap_or_default())
        }
        Err(_) => (502, "text/plain".to_owned(), Bytes::new()),
    };
    let served = served_models(&answer);
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let message = |index: usize| {
        request["messages"][index]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    // An answer that names no model is not attested, so it is refused too.
    let wrong =
        status == 200 && (served.is_empty() || served.iter().any(|model| *model != relay.served));
    relay.calls.lock().unwrap().push(Call {
        phase: relay.phase.lock().unwrap().clone(),
        system: message(0),
        input: message(1),
        status,
        response_format: request.get("response_format").is_some(),
        served: served
            .into_iter()
            .map(|model| {
                if model == relay.served {
                    model
                } else {
                    ANOTHER_MODEL.to_owned()
                }
            })
            .collect(),
        content: redact_answer(&answer_content(&answer), &relay.key),
        answer_bytes: answer.len(),
    });
    relay.in_flight.fetch_sub(1, Ordering::SeqCst);
    if wrong {
        relay.wrong_model.store(true, Ordering::SeqCst);
        return (StatusCode::BAD_GATEWAY, "another model served this").into_response();
    }
    Response::builder()
        .status(status)
        .header("content-type", kind)
        .body(Body::from(answer))
        .unwrap()
}

/// The forms a log or a report could carry `key` in: the key itself, and its
/// base64 (standard and URL-safe) at each of the three alignments it can
/// start at inside a longer encoded value, cut to the characters the key
/// alone decides.
fn key_forms(key: &str) -> Vec<String> {
    use base64::Engine as _;
    let mut forms = vec![key.to_owned()];
    // The escaped forms a JSON string or a debug print carries the key in.
    let json = serde_json::to_string(key).unwrap();
    let json = &json[1..json.len() - 1];
    forms.push(json.to_owned());
    forms.push(json.replace('/', "\\/"));
    let debug = format!("{key:?}");
    forms.push(debug[1..debug.len() - 1].to_owned());
    // Hex, and percent-encoding of every byte or of the reserved ones only.
    let hex: String = key.bytes().map(|byte| format!("{byte:02x}")).collect();
    forms.push(hex.to_uppercase());
    forms.push(hex);
    let percent = |all: bool| -> String {
        key.bytes()
            .map(|byte| {
                if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
                    char::from(byte).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    };
    forms.push(percent(true).to_lowercase());
    forms.push(percent(true));
    forms.push(percent(false));
    for offset in 0..3 {
        let mut bytes = vec![0_u8; offset];
        bytes.extend_from_slice(key.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&bytes);
        let end = bytes.len() / 3 * 4 + [0, 1, 2][bytes.len() % 3];
        let middle = &encoded[[0, 2, 3][offset].min(end)..end];
        // Too short a cut would match anything.
        if middle.len() >= 8 {
            forms.push(middle.to_owned());
            forms.push(middle.replace('+', "-").replace('/', "_"));
        }
    }
    forms.sort();
    forms.dedup();
    forms
}

/// `text` with every form of `key` cut out: a provider's error body may echo
/// the key it refused.
fn redact(text: &str, key: &str) -> String {
    key_forms(key).iter().fold(text.to_owned(), |text, form| {
        text.replace(form, "[provider key]")
    })
}

/// Every string in `value`, keys included, with `key` cut out of its decoded
/// text, where no escape can hide it, nested JSON strings included.
fn redact_value(value: &mut Value, key: &str) {
    match value {
        Value::String(text) => *text = redact_text(text, key),
        Value::Array(items) => items.iter_mut().for_each(|item| redact_value(item, key)),
        Value::Object(map) => {
            *map = std::mem::take(map)
                .into_iter()
                .map(|(name, mut item)| {
                    redact_value(&mut item, key);
                    (redact_text(&name, key), item)
                })
                .collect();
        }
        _ => {}
    }
}

/// `text` with `key` cut out. Text that is itself a JSON object or array may
/// carry the key escaped, so it is decoded, redacted and written back in
/// its decoded form (a member a duplicate name hid is dropped with it).
fn redact_text(text: &str, key: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(mut nested @ (Value::Object(_) | Value::Array(_))) => {
            redact_value(&mut nested, key);
            redact(&nested.to_string(), key)
        }
        _ => redact(text, key),
    }
}

/// A provider answer with `key` cut out: a JSON body, or each JSON event of
/// a stream, is decoded first, since JSON may escape any character of it.
fn redact_answer(answer: &str, key: &str) -> String {
    let decoded = |text: &str| {
        serde_json::from_str::<Value>(text).ok().map(|mut value| {
            redact_value(&mut value, key);
            value.to_string()
        })
    };
    let answer = decoded(answer).unwrap_or_else(|| {
        answer
            .lines()
            .map(|line| {
                line.strip_prefix("data:")
                    .and_then(|data| decoded(data.trim()))
                    .map_or_else(|| line.to_owned(), |event| format!("data: {event}"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    redact(&answer, key)
}

/// Cuts the key out of every file under `out`, returning the files it was in.
fn scrub(out: &Path, key: &str) -> Vec<PathBuf> {
    let forms = key_forms(key);
    let mut found = Vec::new();
    for path in std::fs::read_dir(out)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
    {
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        let literal = forms.iter().any(|form| text.contains(form));
        if literal || decoded_carries(&text, key) {
            if literal {
                std::fs::write(&path, redact(&text, key)).unwrap();
            }
            found.push(path);
        }
    }
    found
}

/// Whether a decoded JSON string in `text` carries `key`: the whole text or
/// a line's trailing JSON, nested JSON strings included, since JSON may
/// escape any character of it.
fn decoded_carries(text: &str, key: &str) -> bool {
    fn carries(value: &Value, key: &str) -> bool {
        match value {
            Value::String(text) => {
                text.contains(key)
                    || serde_json::from_str::<Value>(text).is_ok_and(|nested| carries(&nested, key))
            }
            Value::Array(items) => items.iter().any(|item| carries(item, key)),
            Value::Object(map) => map
                .iter()
                .any(|(name, item)| name.contains(key) || carries(item, key)),
            _ => false,
        }
    }
    std::iter::once(text)
        .chain(
            text.lines()
                .filter_map(|line| line.find('{').map(|start| &line[start..])),
        )
        .filter_map(|json| serde_json::from_str::<Value>(json).ok())
        .any(|value| carries(&value, key))
}

/// The model ids an answer names: a JSON body's, or every stream event's.
fn served_models(answer: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(answer);
    let mut models: Vec<String> = match serde_json::from_str::<Value>(&text) {
        Ok(body) => body["model"]
            .as_str()
            .map(str::to_owned)
            .into_iter()
            .collect(),
        Err(_) => text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
            .filter_map(|event| event["model"].as_str().map(str::to_owned))
            .collect(),
    };
    models.dedup();
    models
}

/// The assistant text an answer carries, as the server reads it: a JSON
/// body's first choice's message content, or a stream's first-choice content
/// deltas joined in order. A first choice whose index is present and not 0
/// is kept by no one: the server refuses a nonzero one, and nothing of a
/// malformed one is kept.
fn answer_content(answer: &[u8]) -> String {
    let first = |event: &Value| -> Option<Value> {
        let choice = event["choices"].get(0)?;
        choice
            .get("index")
            .is_none_or(|index| index.as_u64() == Some(0))
            .then(|| choice.clone())
    };
    let text = String::from_utf8_lossy(answer);
    match serde_json::from_str::<Value>(&text) {
        Ok(body) => first(&body)
            .and_then(|choice| choice["message"]["content"].as_str().map(str::to_owned))
            .unwrap_or_default(),
        Err(_) => text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
            .filter_map(|event| {
                first(&event)
                    .and_then(|choice| choice["delta"]["content"].as_str().map(str::to_owned))
            })
            .collect(),
    }
}

/// One direct call before anything else: the provider must answer as the
/// model the run expects, or the run stops here.
async fn probe(live: &Live) -> Value {
    let answer: Value = no_redirects()
        .post(format!("{}/v1/chat/completions", live.origin))
        .bearer_auth(&live.key)
        .json(&json!({
            "model": live.model,
            "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
            "max_tokens": 16,
        }))
        .send()
        .await
        .unwrap_or_else(|_| panic!("the provider did not answer the probe"))
        .json()
        .await
        .unwrap_or_else(|_| panic!("the provider's probe answer is not JSON"));
    // The message names neither model: the provider chose the one it sent.
    assert!(
        answer["model"].as_str() == Some(live.served.as_str()),
        "the provider served another model; stopping"
    );
    answer
}

/// A client that never follows a redirect, so no provider-chosen location
/// reaches an error the run prints.
fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn models_section(relay: &str, live: &Live) -> String {
    format!(
        r#"
[models]
default = "live:{model}"
extraction_egress = true

[models.providers.live]
kind = "openai-compat"
base_url = "{relay}"
key_env = "{KEY_ENV}"
timeout_secs = {PROVIDER_TIMEOUT_SECS}
response_format = "{response_format}"

[models.dreamer]
summary_prompt = "Summarize these records in two plain sentences."
"#,
        model = live.model,
        response_format = live.response_format
    )
}

fn serve(config: &Path, live: &Live, log: &Path) -> Child {
    let log = std::fs::File::create(log).unwrap();
    oneiron(config, &["serve"])
        .env(
            "RUST_LOG",
            "warn,oneiron::run_receipt=info,oneiron::dreamer=info",
        )
        .env("NO_COLOR", "1")
        .env(KEY_ENV, &live.key)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap()
}

fn kill(mut child: Child) {
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The invented speaker, as a PERSON the passage can name.
fn speaker(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({"name": "Mira Okafor"})).unwrap(),
        )
        .unwrap();
    person
}

/// One user turn in `conversation`, witnessed while the server is stopped.
fn witness(vault: &Vault, person: EntityId, conversation: EntityId, text: &str) -> EntityId {
    let turn = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: vault.now_recorded_at() + 1,
        })
        .unwrap();
    turn
}

/// Every claim in the vault with its approval, lifecycle and what it closes.
fn claims(vault: &Vault) -> Vec<Value> {
    vault
        .entities_by_type(ENTITY_TYPE_CLAIM)
        .unwrap()
        .into_iter()
        .filter_map(|id| Some((id, vault.get_claim(&id).ok().flatten()?)))
        .filter(|(_, body)| {
            !body.predicate.starts_with("policy.") && !body.predicate.starts_with("machine.")
        })
        .map(|(id, body)| {
            // A Dreamer step record holds the provider's whole answer, so the
            // report keeps only its size.
            let value = if body.predicate.starts_with("dreamer.") {
                json!({"omitted_bytes": format!("{:?}", body.value).len()})
            } else {
                json!(format!("{:?}", body.value))
            };
            let supersedes: Vec<_> = vault
                .edges_out(&id)
                .unwrap()
                .into_iter()
                .filter(|edge| edge.kind == oneiron::edge::EdgeKind::Supersedes)
                .map(|edge| edge.target.to_hex())
                .collect();
            json!({
                "id": id.to_hex(),
                "subject": format!("{:?}", body.subject),
                "predicate": body.predicate,
                "value": value,
                "source": format!("{:?}", body.source),
                "approval": format!("{:?}", body.approval),
                "lifecycle": format!("{:?}", body.lifecycle),
                "supersedes": supersedes,
                "pending_supersedes": vault
                    .pending_claim_supersession(&id)
                    .unwrap()
                    .map(|prior| prior.to_hex()),
            })
        })
        .collect()
}

/// `person`'s claims, each with the replacements that close it.
fn about(vault: &Vault, person: EntityId) -> Vec<(EntityId, oneiron::ClaimBody, Vec<EntityId>)> {
    let rows: Vec<_> = vault
        .claims_for_subject(&person)
        .unwrap()
        .into_iter()
        .filter_map(|id| Some((id, vault.get_claim(&id).ok().flatten()?)))
        .collect();
    let closes = |id: EntityId| -> Vec<EntityId> {
        vault
            .edges_out(&id)
            .unwrap()
            .into_iter()
            .filter(|edge| edge.kind == oneiron::edge::EdgeKind::Supersedes)
            .map(|edge| edge.target)
            .collect()
    };
    rows.iter()
        .map(|(id, body)| {
            let by = rows
                .iter()
                .filter(|(other, _)| closes(*other).contains(id))
                .map(|(other, _)| *other)
                .collect();
            (*id, body.clone(), by)
        })
        .collect()
}

fn names(body: &oneiron::ClaimBody, place: &str) -> bool {
    format!("{:?}", body.value).contains(place)
}

/// The first pass's fact: an Active claim about `person` naming Lisbon.
fn lisbon_stated(vault: &Vault, person: EntityId) -> Result<(), String> {
    let about = about(vault, person);
    about
        .iter()
        .any(|(_, body, _)| {
            names(body, "Lisbon") && body.lifecycle == oneiron::ClaimLifecycleStatus::Active
        })
        .then_some(())
        .ok_or_else(|| format!("no Active claim about the speaker names Lisbon: {about:?}"))
}

/// The correction, held once: an Active Auto claim naming Porto closes a
/// claim naming Lisbon, no claim is closed by two replacements, and no
/// Active claim naming Lisbon is left on the corrected predicate.
fn corrected_once(vault: &Vault, person: EntityId) -> Result<(), String> {
    let about = about(vault, person);
    let active =
        |body: &oneiron::ClaimBody| body.lifecycle == oneiron::ClaimLifecycleStatus::Active;
    let bound: Vec<_> = about
        .iter()
        .filter(|(_, prior, _)| names(prior, "Lisbon"))
        .flat_map(|(_, prior, by)| by.iter().map(move |replacement| (prior, *replacement)))
        .filter_map(|(prior, replacement)| {
            let (_, body, _) = about.iter().find(|(id, _, _)| *id == replacement)?;
            (names(body, "Porto")
                && active(body)
                && body.approval == oneiron::ClaimApprovalStatus::Auto
                && prior.lifecycle == oneiron::ClaimLifecycleStatus::Superseded)
                .then_some(body)
        })
        .collect();
    if bound.is_empty() {
        return Err(format!("no Porto claim closed a Lisbon claim: {about:?}"));
    }
    if let Some((id, _, by)) = about.iter().find(|(_, _, by)| by.len() > 1) {
        return Err(format!(
            "{} was closed by {} replacements",
            id.to_hex(),
            by.len()
        ));
    }
    if about.iter().any(|(_, body, _)| {
        names(body, "Lisbon")
            && active(body)
            && bound.iter().any(|porto| porto.predicate == body.predicate)
    }) {
        return Err(format!(
            "an Active Lisbon claim is left beside the correction: {about:?}"
        ));
    }
    Ok(())
}

/// The receipts in this run's server `logs`, one JSON row each.
fn receipts(logs: &[PathBuf]) -> Vec<Value> {
    logs.iter()
        .flat_map(|log| {
            std::fs::read_to_string(log)
                .unwrap_or_default()
                .lines()
                .filter(|line| line.contains("oneiron::run_receipt"))
                .filter_map(|line| line.split_once(" row=").map(|(_, row)| row.to_owned()))
                .filter_map(|row| serde_json::from_str::<Value>(&row).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A receipt as the report keeps it: the fields the run checks. A served
/// model other than `served` and any error text are replaced by what they
/// say, since the provider may have chosen their words; the serve logs keep
/// the rows whole.
fn receipt_summary(row: &Value, served: &str) -> Value {
    json!({
        "event": row["event"],
        "run": row["run"],
        "lease": row["lease"],
        "answered": row["answered"],
        "served_model": match row["served_model"].as_str() {
            Some(model) if model == served => json!(model),
            Some(_) => json!(ANOTHER_MODEL),
            None => Value::Null,
        },
        "error": !row["error"].is_null(),
        "allocation_error": !row["allocation_error"].is_null(),
    })
}

/// What the run has found so far. The report is written from it whether the
/// run passes or fails.
#[derive(Default)]
struct Notes(Mutex<serde_json::Map<String, Value>>);

impl Notes {
    fn put(&self, key: &str, value: Value) {
        self.0.lock().unwrap().insert(key.to_owned(), value);
    }

    fn push(&self, key: &str, value: Value) {
        let mut notes = self.0.lock().unwrap();
        let list = notes.entry(key).or_insert_with(|| json!([]));
        list.as_array_mut().unwrap().push(value);
    }
}

/// The server a phase runs, held outside the phase so that a failing phase's
/// server is still stopped before the report is written.
#[derive(Default)]
struct Running(Mutex<Option<Child>>);

impl Running {
    fn start(&self, child: Child) {
        *self.0.lock().unwrap() = Some(child);
    }

    fn take(&self) -> Option<Child> {
        self.0.lock().unwrap().take()
    }
}

/// Stops the server gracefully. A pass in flight runs its attempt to the end,
/// model calls included, so the grace covers one provider call; past it the
/// server is killed by its exact PID. Each stop is noted with how the server
/// exited; only a zero exit after SIGTERM is clean.
fn halt(child: Option<Child>, phase: &str, notes: &Notes) {
    let Some(mut child) = child else {
        return;
    };
    let started = Instant::now();
    let mut status = child.try_wait().unwrap();
    // A server that already exited is noted as it exited, never signalled.
    let signalled = status.is_none();
    if signalled {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let grace = Duration::from_secs(PROVIDER_TIMEOUT_SECS + 30);
        while status.is_none() && started.elapsed() < grace {
            std::thread::sleep(Duration::from_millis(100));
            status = child.try_wait().unwrap();
        }
    }
    let killed = status.is_none();
    if killed {
        kill(child);
    }
    notes.push(
        "stops",
        json!({
            "phase": phase,
            "secs": started.elapsed().as_secs_f64(),
            "killed": killed,
            "exit": status.map(|status| status.to_string()),
            "clean": signalled && status.is_some_and(|status| status.success()),
        }),
    );
}

fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "a panic with no message".to_owned())
}

#[tokio::test]
#[ignore = "calls a real model provider; run with --ignored and the ONEIRON_LIVE_* environment"]
async fn dreamer_live_consolidates_corrects_and_survives_restarts_on_a_real_model() {
    use futures_util::FutureExt as _;
    let live = Live::from_env();
    // Every panic message is redacted before it is printed: a panic can
    // carry the server's or a provider's text.
    let default_hook = std::panic::take_hook();
    let key = live.key.clone();
    std::panic::set_hook(Box::new(move |info| {
        let place = info
            .location()
            .map_or_else(String::new, |at| format!(" at {}:{}", at.file(), at.line()));
        eprintln!(
            "panicked{place}: {}",
            redact_text(&panic_text(info.payload()), &key)
        );
    }));
    let (relay, relay_url) = Relay::start(&live).await;
    let logs: Vec<_> = (1..=5)
        .map(|n| live.out.join(format!("serve-{n}.log")))
        .collect();
    // Only this run's logs and report: a log a phase never reached is absent.
    for stale in logs.iter().chain([&live.out.join("report.json")]) {
        let _ = std::fs::remove_file(stale);
    }
    let dir = tempfile::tempdir().unwrap();
    let notes = Notes::default();
    let running = Running::default();
    let run = std::panic::AssertUnwindSafe(run(
        &live,
        &relay,
        &relay_url,
        &logs,
        dir.path(),
        &running,
        &notes,
    ))
    .catch_unwind()
    .await;
    if let Err(panic) = &run {
        notes.put("failure", json!(panic_text(panic.as_ref())));
        // The failing phase's server stops before its logs are read.
        halt(running.take(), "after the failure", &notes);
    }
    notes.put("calls", json!(relay.calls()));
    notes.put(
        "in_flight_at_end",
        json!(relay.in_flight.load(Ordering::SeqCst)),
    );
    let kept: Vec<_> = receipts(&logs)
        .iter()
        .map(|row| receipt_summary(row, &live.served))
        .collect();
    notes.put("receipts", json!(kept));
    // The key scan runs before the report, so a leak is in the report too.
    let mut leaked = scrub(&live.out, &live.key);
    if !leaked.is_empty() {
        notes.put("key_found_in", json!(leaked));
    }
    let mut report = Value::Object(notes.0.into_inner().unwrap());
    redact_value(&mut report, &live.key);
    std::fs::write(
        live.out.join("report.json"),
        redact(&serde_json::to_string_pretty(&report).unwrap(), &live.key),
    )
    .unwrap();
    leaked.extend(scrub(&live.out, &live.key));
    std::panic::set_hook(default_hook);
    assert!(leaked.is_empty(), "the provider key reached {leaked:?}");
    if let Err(panic) = run {
        std::panic::resume_unwind(panic);
    }
}

async fn run(
    live: &Live,
    relay: &Relay,
    relay_url: &str,
    logs: &[PathBuf],
    dir: &Path,
    running: &Running,
    notes: &Notes,
) {
    notes.put("model_asked", json!(live.model));
    notes.put("model_expected", json!(live.served));
    let probe = probe(live).await;
    notes.put("probe_model", probe["model"].clone());
    let vault_path = dir.join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let config = write_config(
        dir,
        &vault_path,
        free_port(),
        &models_section(relay_url, live),
    );
    // Before the queue: the conversation and its summary declaration land
    // while no server runs; the server queues the turn's pass at start.
    let conversation = EntityId::now();
    let (person, first_turn) = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let person = speaker(&vault);
        let turn = witness(
            &vault,
            person,
            conversation,
            "Hi, I'm Mira Okafor. I live in Lisbon and I teach cello at the conservatory.",
        );
        vault
            .request_scope_summary(&ScopeSummaryRequest {
                target: ScopeSummaryTarget::Scope {
                    scope: ScopeSelector {
                        conversation,
                        session: None,
                        path: ScopePath::Canonical,
                        include_forks: false,
                    },
                    land_on: None,
                    as_record: false,
                },
                requester: WriteActor::new(person, EdgeActorClass::Human),
            })
            .unwrap();
        (person, turn)
    };
    notes.put("person", json!(person.to_hex()));
    notes.put("turns", json!([first_turn.to_hex()]));

    // The Dreamer's grant, on the vault the witness opened.
    let granted = oneiron(
        &config,
        &["dreamer", "grant", "--extraction-route", "third_party"],
    )
    .output()
    .unwrap();
    assert!(
        granted.status.success(),
        "grant: {}",
        String::from_utf8_lossy(&granted.stderr)
    );

    // 1. Between queue and apply: the first call is held and never sent.
    relay.enter("held");
    relay.hold.store(true, Ordering::SeqCst);
    running.start(serve(&config, live, &logs[0]));
    tokio::time::timeout(PHASE, relay.holding.notified())
        .await
        .expect("the server's first pass reached its model call");
    kill(running.take().unwrap());

    // 2. After apply: the passes run on the real model and land.
    relay.enter("consolidate");
    running.start(serve(&config, live, &logs[1]));
    relay.settle(1).await;
    kill(running.take().unwrap());
    let consolidated = relay.calls().len();

    // 3. Nothing finished runs again.
    relay.enter("restart");
    running.start(serve(&config, live, &logs[2]));
    relay.settle(0).await;
    halt(running.take(), "restart", notes);
    let after_restart = relay.calls().len();
    let first = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let summaries = vault.entities_by_type(ENTITY_TYPE_SUMMARY).unwrap();
        (
            claims(&vault),
            summaries.len(),
            lisbon_stated(&vault, person),
        )
    };
    notes.put("claims_after_consolidation", json!(first.0));
    notes.put("summaries_after_consolidation", json!(first.1));
    notes.put("lisbon_stated", json!(first.2.as_ref().err()));

    // 4. A user correction in a later conversation, heard by a later pass.
    // The first conversation's summary moved it onto the record DAG, which
    // the witness door no longer appends to.
    // Beside it, the owner states an instrument and a third conversation
    // changes it. A Dreamer correction of the owner's claim never skips the
    // verdict (the source check), so the verdict role makes a real call.
    let (second_turn, third_turn) = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        vault
            .memory(owner, EdgeActorClass::Human)
            .claim_upsert(
                &serde_json::from_value(json!({
                    "predicate": "music.instrument", "subject_ref": person.to_hex(),
                    "value": "violin", "confidence": 1.0, "source": "observed",
                }))
                .unwrap(),
            )
            .unwrap();
        (
            witness(
                &vault,
                person,
                EntityId::now(),
                "A correction: I moved last month. I live in Porto now, not Lisbon.",
            ),
            witness(
                &vault,
                person,
                EntityId::now(),
                "I switched instruments: I play the viola now, not the violin.",
            ),
        )
    };
    notes.put(
        "turns",
        json!([
            first_turn.to_hex(),
            second_turn.to_hex(),
            third_turn.to_hex()
        ]),
    );
    relay.enter("correct");
    running.start(serve(&config, live, &logs[3]));
    relay.settle(after_restart + 1).await;
    halt(running.take(), "correct", notes);
    let corrected = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        (claims(&vault), corrected_once(&vault, person))
    };
    notes.put("claims_after_correction", json!(corrected.0));
    notes.put("corrected_once", json!(corrected.1.as_ref().err()));

    // 5. The correction holds once.
    relay.enter("hold-once");
    let before_last = relay.calls().len();
    running.start(serve(&config, live, &logs[4]));
    relay.settle(0).await;
    halt(running.take(), "hold-once", notes);
    let last = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        (claims(&vault), corrected_once(&vault, person))
    };
    notes.put("claims_after_last_restart", json!(last.0));
    notes.put("held_after_last_restart", json!(last.1.as_ref().err()));

    assert!(
        !relay.wrong_model.load(Ordering::SeqCst),
        "a call was answered by another model, or by none it named"
    );
    // The findings themselves are in the report.
    assert!(first.2.is_ok(), "the first pass stated no Lisbon claim");
    assert!(first.1 > 0, "the declared summary landed");
    assert!(corrected.1.is_ok(), "the correction did not land once");
    assert!(
        last.1.is_ok(),
        "the correction did not hold after a restart"
    );
    assert_eq!(after_restart, consolidated, "a finished pass called again");
    assert_eq!(
        relay.calls().len(),
        before_last,
        "a finished correction called again"
    );
    assert!(last.0 == corrected.0, "the correction did not hold once");
    let receipts = receipts(logs);
    for row in receipts
        .iter()
        .filter(|row| row["event"] == "dispatched" && row["answered"] == true)
    {
        assert!(
            row["served_model"] == json!(live.served),
            "an answered call's receipt names another model"
        );
    }
    // The instrument: the verdict role's call was answered by the expected
    // model and settled, whichever way it ruled.
    let verdict: Vec<&Value> = receipts
        .iter()
        .filter(|row| row["run"] == "dreamer-pass/generative_reasoner")
        .collect();
    assert!(
        verdict.iter().any(|dispatched| {
            dispatched["event"] == "dispatched"
                && dispatched["answered"] == true
                && dispatched["served_model"] == json!(live.served)
                && verdict.iter().any(|settled| {
                    settled["event"] == "settled"
                        && settled["lease"] == dispatched["lease"]
                        && settled["error"].is_null()
                        && settled["allocation_error"].is_null()
                })
        }),
        "the verdict role's answered call did not settle"
    );
    // Every server stopped on SIGTERM within its grace, with a zero exit.
    let stops = notes.0.lock().unwrap()["stops"].clone();
    assert!(
        stops
            .as_array()
            .unwrap()
            .iter()
            .all(|stop| stop["clean"] == true),
        "a server did not stop cleanly on SIGTERM: {stops}"
    );
}
