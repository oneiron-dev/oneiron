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
//!   `report.json`.
//!
//! On invented data it witnesses a short conversation and declares its
//! summary while the server is stopped, so the server queues the work at
//! start (the kill before the queue). Then it:
//! 1. serves with the first model call held at the relay, and kills the
//!    server while it is held (between queue and apply);
//! 2. serves until the passes land, and kills the server (after apply);
//! 3. serves again: a finished pass makes no call;
//! 4. witnesses a user correction and serves until it is consolidated;
//! 5. serves again: the correction holds once.
//!
//! Every model call goes through a relay that forwards it unchanged and keeps
//! the model id each answer names. The server's Admitted, Dispatched and
//! Settled receipts are kept from its log.
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

use crate::ai_serve::{free_port, oneiron, stop, vault_config, write_config};

/// The provider key's variable in the server's environment.
const KEY_ENV: &str = "ONEIRON_LIVE_PROVIDER_KEY";
/// A quiet spell this long with no call in flight means the passes are done.
const QUIET: Duration = Duration::from_secs(20);
/// The longest one phase waits for the server's model calls.
const PHASE: Duration = Duration::from_secs(600);

struct Live {
    origin: String,
    model: String,
    served: String,
    key: String,
    out: PathBuf,
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
    served: Vec<String>,
    answer: String,
}

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
            client: reqwest::Client::new(),
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
        served,
        answer: redact(&String::from_utf8_lossy(&answer), &relay.key),
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
    forms.dedup();
    forms
}

/// `text` with every form of `key` cut out: a provider's error body may echo
/// the key it refused.
fn redact(text: &str, key: &str) -> String {
    key_forms(key)
        .iter()
        .fold(text.to_owned(), |text, form| text.replace(form, "[provider key]"))
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
        if forms.iter().any(|form| text.contains(form)) {
            std::fs::write(&path, redact(&text, key)).unwrap();
            found.push(path);
        }
    }
    found
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

/// One direct call before anything else: the provider must answer as the
/// model the run expects, or the run stops here.
async fn probe(live: &Live) -> Value {
    let answer: Value = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", live.origin))
        .bearer_auth(&live.key)
        .json(&json!({
            "model": live.model,
            "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
            "max_tokens": 16,
        }))
        .send()
        .await
        .expect("the provider answers")
        .json()
        .await
        .expect("the provider answers JSON");
    assert_eq!(
        answer["model"].as_str(),
        Some(live.served.as_str()),
        "the provider served another model; stopping"
    );
    answer
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
timeout_secs = 300

[models.dreamer]
summary_prompt = "Summarize these records in two plain sentences."
"#,
        model = live.model
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
                "value": format!("{:?}", body.value),
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
    let active = |body: &oneiron::ClaimBody| body.lifecycle == oneiron::ClaimLifecycleStatus::Active;
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
        return Err(format!("{} was closed by {} replacements", id.to_hex(), by.len()));
    }
    if about.iter().any(|(_, body, _)| {
        names(body, "Lisbon")
            && active(body)
            && bound.iter().any(|porto| porto.predicate == body.predicate)
    }) {
        return Err(format!("an Active Lisbon claim is left beside the correction: {about:?}"));
    }
    Ok(())
}

/// The receipts in the server logs under `out`, one JSON row each.
fn receipts(out: &Path) -> Vec<Value> {
    let mut logs: Vec<_> = std::fs::read_dir(out)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
        .collect();
    logs.sort();
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

#[tokio::test]
#[ignore = "calls a real model provider; run with --ignored and the ONEIRON_LIVE_* environment"]
async fn dreamer_live_consolidates_corrects_and_survives_restarts_on_a_real_model() {
    let live = Live::from_env();
    let probe = probe(&live).await;
    let (relay, relay_url) = Relay::start(&live).await;
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let config = write_config(
        dir.path(),
        &vault_path,
        free_port(),
        &models_section(&relay_url, &live),
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
    let child = serve(&config, &live, &live.out.join("serve-1.log"));
    tokio::time::timeout(PHASE, relay.holding.notified())
        .await
        .expect("the server's first pass reached its model call");
    kill(child);

    // 2. After apply: the passes run on the real model and land.
    relay.enter("consolidate");
    let child = serve(&config, &live, &live.out.join("serve-2.log"));
    relay.settle(1).await;
    kill(child);
    let consolidated = relay.calls().len();

    // 3. Nothing finished runs again.
    relay.enter("restart");
    let child = serve(&config, &live, &live.out.join("serve-3.log"));
    tokio::time::sleep(QUIET).await;
    stop(child);
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

    // 4. A user correction, heard by a later pass.
    let second_turn = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        witness(
            &vault,
            person,
            conversation,
            "A correction: I moved last month. I live in Porto now, not Lisbon.",
        )
    };
    relay.enter("correct");
    let child = serve(&config, &live, &live.out.join("serve-4.log"));
    relay.settle(after_restart + 1).await;
    stop(child);
    let corrected = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        (claims(&vault), corrected_once(&vault, person))
    };

    // 5. The correction holds once.
    relay.enter("hold-once");
    let before_last = relay.calls().len();
    let child = serve(&config, &live, &live.out.join("serve-5.log"));
    tokio::time::sleep(QUIET).await;
    stop(child);
    let last = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        (claims(&vault), corrected_once(&vault, person))
    };

    let calls = relay.calls();
    let receipts = receipts(&live.out);
    let report = json!({
        "model_asked": live.model,
        "model_expected": live.served,
        "probe_model": probe["model"],
        "person": person.to_hex(),
        "turns": [first_turn.to_hex(), second_turn.to_hex()],
        "calls": calls,
        "claims_after_consolidation": first.0,
        "summaries_after_consolidation": first.1,
        "lisbon_stated": first.2.as_ref().err(),
        "claims_after_correction": corrected.0,
        "corrected_once": corrected.1.as_ref().err(),
        "claims_after_last_restart": last.0,
        "held_after_last_restart": last.1.as_ref().err(),
        "receipts": receipts,
    });
    std::fs::write(
        live.out.join("report.json"),
        redact(&serde_json::to_string_pretty(&report).unwrap(), &live.key),
    )
    .unwrap();
    let leaked = scrub(&live.out, &live.key);
    assert!(leaked.is_empty(), "the provider key reached {leaked:?}");

    assert!(
        !relay.wrong_model.load(Ordering::SeqCst),
        "a call was answered by another model, or by none it named"
    );
    first.2.unwrap();
    assert!(first.1 > 0, "the declared summary landed");
    corrected.1.unwrap();
    last.1.unwrap();
    assert_eq!(after_restart, consolidated, "a finished pass called again");
    assert_eq!(
        relay.calls().len(),
        before_last,
        "a finished correction called again"
    );
    assert_eq!(last.0, corrected.0, "the correction did not hold once");
    for row in receipts
        .iter()
        .filter(|row| row["event"] == "dispatched" && row["answered"] == true)
    {
        assert_eq!(row["served_model"], json!(live.served), "{row}");
    }
}
