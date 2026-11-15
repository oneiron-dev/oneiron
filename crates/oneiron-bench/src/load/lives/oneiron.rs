//! The Oneiron store of the lives screen: the shipped `oneiron-server`
//! spawned on loopback and called as a minted full-access agent (the
//! measuring mode, Linux only), or the engine linked into this bench, served
//! in this process and called as the vault owner (for checking the harness;
//! it runs anywhere, and the CLI tests use it).
//!
//! Ingest is one `vault.witness` per turn with one message: `user` for the
//! user, `companion` for the assistant, and `companion` with message type
//! `tool_result` for a tool turn. Then the bench waits for the server to go
//! quiet (and, with an embedder, for its embedding passes to stop) and asks
//! every question with `vault.recall` at every grade, one at a time.

use std::collections::BTreeMap;
use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::authority::{CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer};
use serde_json::{Value, json};

use super::super::client::Agent;
use super::super::corpus_recall::settle;
use super::super::phases::{PASS_DONE, PASS_FAILED};
use super::super::server::{Embedding, Running, Vault, cpu_seconds};
use super::super::stats::{Sample, Summary};
use super::corpus::{Life, Role, Turn};
use super::report::{Answer, Row, Server, System, summarize};
use super::{Mode, Plan, say};

/// The longest wait for an embedder's passes to stop.
const DRAIN_CAP: Duration = Duration::from_secs(3_600);

enum Store {
    Spawned { server: Running, vault: Vault },
    InProcess(InProcess),
}

fn describe(embedding: &Embedding) -> String {
    match embedding {
        Embedding::None => "none".to_owned(),
        Embedding::Local => "local".to_owned(),
        Embedding::Stub { .. } => "stub".to_owned(),
        Embedding::Endpoint { model_id, .. } => format!("endpoint {model_id}"),
    }
}

impl Store {
    fn open(
        plan: &Plan,
        dir: &Path,
        http: &reqwest::blocking::Client,
    ) -> Result<(Self, Agent, Server), String> {
        match &plan.mode {
            Mode::Spawned { bin, embedding } => {
                let vault = Vault::init(bin, dir, embedding, &plan.server_env)?;
                let credential = vault.mint_agent(bin, "lives-bench-agent")?;
                let server = Running::start(bin, &vault, &plan.server_env, "serve.log", "warn")?;
                say(&format!("server ready in {:.0} ms", server.ready_ms));
                let agent = Agent::new(http, &server.base, &credential, 0)?;
                let info = Server {
                    mode: "spawned",
                    bin: Some(bin.display().to_string()),
                    bytes: Some(
                        std::fs::metadata(bin)
                            .map_err(|e| format!("--server: {e}"))?
                            .len(),
                    ),
                    principal: "agent",
                    embedder: describe(embedding),
                };
                Ok((Self::Spawned { server, vault }, agent, info))
            }
            Mode::InProcess => {
                let (served, root, issuer) = InProcess::start(dir)?;
                let agent = Agent::host_root(http, &served.base, root, issuer)?;
                let info = Server {
                    mode: "in_process",
                    bin: None,
                    bytes: None,
                    principal: "owner",
                    embedder: describe(&Embedding::None),
                };
                Ok((Self::InProcess(served), agent, info))
            }
        }
    }

    /// The process whose CPU the settle watches.
    fn pid(&self) -> u32 {
        match self {
            Self::Spawned { server, .. } => server.pid,
            Self::InProcess(_) => std::process::id(),
        }
    }

    fn disk_mib(&self) -> Option<f64> {
        match self {
            Self::Spawned { vault, .. } => Some(vault.disk_bytes() as f64 / 1_048_576.0),
            Self::InProcess(_) => None,
        }
    }

    fn stop(self) -> String {
        match self {
            Self::Spawned { server, .. } => server.stop(),
            Self::InProcess(served) => served.stop(),
        }
    }
}

/// Waits until the server's embedding passes stop: at least one pass, then
/// `quiet` with no further pass. An error when the server exits or logs a
/// failed pass.
fn drain(server: &Running, quiet: Duration) -> Result<f64, String> {
    let started = Instant::now();
    let mut passes = server.log_count(PASS_DONE);
    let mut since = Instant::now();
    while started.elapsed() < DRAIN_CAP {
        std::thread::sleep(Duration::from_secs(1));
        if cpu_seconds(server.pid).is_none() {
            return Err("drain: the server has exited".into());
        }
        if server.logged(PASS_FAILED) {
            return Err(format!("drain: the server logged `{PASS_FAILED}`"));
        }
        let now = server.log_count(PASS_DONE);
        if now != passes {
            passes = now;
            since = Instant::now();
        }
        if passes > 0 && since.elapsed() >= quiet {
            return Ok(started.elapsed().as_secs_f64());
        }
    }
    Err(format!(
        "drain: embedding passes still running after {} s",
        DRAIN_CAP.as_secs()
    ))
}

fn witness_body(turn: &Turn) -> Value {
    let (author, message_type) = match turn.role {
        Role::User => ("user", "text"),
        Role::Assistant => ("companion", "text"),
        Role::Tool => ("companion", "tool_result"),
    };
    json!({
        "conversation_ref": turn.conversation,
        "occurred_at": turn.at,
        "messages": [{
            "author": author,
            "message_type": message_type,
            "content": turn.text,
            "is_visible": true,
            "order": 0,
        }],
    })
}

fn recall_body(query: &str, grade: &str, limit: usize, as_of: u64) -> Value {
    json!({"query": query, "effort": grade, "limit": limit, "as_of": as_of})
}

/// Each item's texts, in rank order: its own text, then each message it cites.
fn texts(pack: &Value) -> Vec<Vec<String>> {
    pack["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    std::iter::once(&item["value_text"])
                        .chain(
                            item["cited_messages"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .map(|m| &m["value_text"]),
                        )
                        .filter_map(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every question of every life at every grade, each at the end of its own
/// life's last day (`as_of` only anchors a question's time words and recency,
/// and filters nothing), so "last week" reads on that person's timeline;
/// returns the rows and each grade's wall time.
fn ask(plan: &Plan, agent: &Agent, lives: &[Life]) -> (Vec<Row>, BTreeMap<String, f64>) {
    let mut rows = Vec::new();
    let mut seconds = BTreeMap::new();
    let warm = lives.iter().find_map(|life| {
        life.questions
            .first()
            .map(|(_, question)| (question.question.clone(), life.end))
    });
    for grade in &plan.grades {
        say(&format!("ask: grade {grade}"));
        // One untimed recall first, so the grade's first row is not a cold start.
        if let Some((query, as_of)) = &warm {
            let _ = agent.post(
                "vault.recall",
                &recall_body(query, grade, plan.limit, *as_of),
            );
        }
        let started = Instant::now();
        for life in lives {
            for (set, question) in &life.questions {
                let body = recall_body(&question.question, grade, plan.limit, life.end);
                let (ms, result) = agent.post("vault.recall", &body);
                let answer = match result {
                    Ok(pack) => Answer {
                        ms,
                        system_ms: None,
                        partial: pack["retrieval_meta"]["partial"].as_bool() == Some(true),
                        items: texts(&pack),
                        error: None,
                    },
                    Err(error) => Answer {
                        ms,
                        system_ms: None,
                        partial: false,
                        items: Vec::new(),
                        error: Some(error),
                    },
                };
                rows.push(Row::of("oneiron", grade, life, *set, question, answer));
            }
        }
        seconds.insert(grade.clone(), started.elapsed().as_secs_f64());
    }
    (rows, seconds)
}

/// Ingests `lives` into a fresh Oneiron store and asks their questions.
pub(super) fn measure(plan: &Plan, lives: &[Life]) -> Result<(Server, System), String> {
    let dir = plan.work.join("lives-oneiron");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clear {}: {e}", dir.display()))?;
    }
    let http = Agent::http()?;
    let (store, mut agent, server) = Store::open(plan, &dir, &http)?;
    let skew = agent.clock_skew()?;
    if skew != 0 {
        say(&format!(
            "holder proofs are signed {skew} s off the wall clock"
        ));
    }
    let turns = lives.iter().map(|life| life.turns.len()).sum::<usize>();
    say(&format!("ingest: {turns} turns of {} lives", lives.len()));
    let started = Instant::now();
    let mut samples = Vec::with_capacity(turns);
    for turn in lives.iter().flat_map(|life| &life.turns) {
        let (ms, result) = agent.post("vault.witness", &witness_body(turn));
        samples.push(Sample {
            ms,
            error: result.err(),
            partial: false,
            items: 1,
        });
    }
    let ingest = Summary::of(&samples, started.elapsed().as_secs_f64());
    let documents = ingest.completed;
    if documents == 0 && turns > 0 {
        return Err(format!(
            "ingest: every witness failed: {:?}",
            ingest.failures
        ));
    }
    let settle_seconds = settle(store.pid(), plan.settle_max);
    say(&format!("settled after {settle_seconds:.1} s"));
    let drain_seconds = match (&store, &plan.mode) {
        (Store::Spawned { server, .. }, Mode::Spawned { embedding, .. })
            if !matches!(embedding, Embedding::None) =>
        {
            say("drain: waiting for the embedding passes to stop");
            Some(drain(server, plan.drain_settle)?)
        }
        _ => None,
    };
    let (rows, seconds) = ask(plan, &agent, lives);
    let disk_mib = store.disk_mib();
    say(&format!("oneiron store: {}", store.stop()));
    Ok((
        server,
        System {
            name: "oneiron".to_owned(),
            status: "measured",
            reason: None,
            documents,
            ingest: ingest.below_corpus_floor(documents),
            settle_seconds,
            drain_seconds,
            disk_mib,
            summary: summarize(&rows, &plan.grades, &seconds, documents),
            rows,
        },
    ))
}

/// What the in-process server thread hands back once it is listening: its
/// base URL, the host root slip and the issuer that rooted the vault.
type Rooted = (String, CapabilitySlip, Arc<HostSlipIssuer>);

/// The engine served in this process, on its own engine-sized runtime.
struct InProcess {
    base: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

/// Opens the vault, roots it with a host issuer the bench draws (the vault
/// holds no keystore, so the server roots nothing; `fleet/workload.rs` roots
/// its vault the same way), and binds a loopback listener.
async fn root_in_process(
    dir: &Path,
) -> Result<(tokio::net::TcpListener, axum::Router, Rooted), String> {
    let vault = Arc::new(
        oneiron::Vault::open(dir, oneiron::VaultConfig::device())
            .map_err(|e| format!("open vault {}: {e}", dir.display()))?,
    );
    let server = Arc::new(
        oneiron_server::server::SyncServer::new(
            Arc::clone(&vault),
            oneiron_server::config::SyncServerConfig {
                auth_secret: Some(oneiron::EntityId::now().to_hex()),
                ..Default::default()
            },
        )
        .map_err(|e| format!("in-process server: {e}"))?,
    );
    let seed: [u8; HOST_ISSUER_SEED_BYTES] = rand::random();
    let issuer = HostSlipIssuer::from_seed(&seed).map_err(|e| format!("host issuer: {e}"))?;
    let root = vault
        .ensure_host_root_slip(&issuer)
        .map_err(|e| format!("host root slip: {e}"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind loopback: {e}"))?;
    let base = format!(
        "http://{}",
        listener
            .local_addr()
            .map_err(|e| format!("bind loopback: {e}"))?
    );
    Ok((
        listener,
        oneiron_server::build_app(server),
        (base, root, Arc::new(issuer)),
    ))
}

/// The server thread's body: a multi-thread runtime whose threads have the
/// engine's stack (the facade's dispatch frame outgrows a default stack in a
/// dev build), serving until `stop` fires.
fn serve_in_process(
    dir: &Path,
    ready: &std::sync::mpsc::Sender<Result<Rooted, String>>,
    stop: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .enable_all()
        .build()
        .map_err(|e| format!("in-process runtime: {e}"));
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };
    let served = runtime.block_on(async {
        let (listener, app, rooted) = match root_in_process(dir).await {
            Ok(opened) => opened,
            Err(error) => {
                let _ = ready.send(Err(error.clone()));
                return Err(error);
            }
        };
        let _ = ready.send(Ok(rooted));
        // Served with each connection's peer, as `build_app` asks of an embedder.
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .into_future();
        tokio::select! {
            result = serve => result.map_err(|e| format!("in-process serve: {e}")),
            _ = stop => Ok(()),
        }
    });
    runtime.shutdown_timeout(Duration::from_secs(10));
    served
}

impl InProcess {
    fn start(dir: &Path) -> Result<(Self, CapabilitySlip, Arc<HostSlipIssuer>), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let owned = dir.to_owned();
        let thread = std::thread::Builder::new()
            .name("lives-in-process".into())
            .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
            .spawn(move || serve_in_process(&owned, &ready_tx, stop_rx))
            .map_err(|e| format!("in-process server thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok((base, root, issuer))) => Ok((
                Self {
                    base,
                    stop: Some(stop_tx),
                    thread: Some(thread),
                },
                root,
                issuer,
            )),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => Err(match thread.join() {
                Ok(Err(error)) => error,
                _ => "the in-process server ended before it was ready".to_owned(),
            }),
        }
    }

    fn shutdown(&mut self) -> String {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take().map(std::thread::JoinHandle::join) {
            Some(Ok(Ok(()))) | None => "stopped".to_owned(),
            Some(Ok(Err(error))) => format!("stopped: {error}"),
            Some(Err(_)) => "the in-process server thread panicked".to_owned(),
        }
    }

    fn stop(mut self) -> String {
        self.shutdown()
    }
}

impl Drop for InProcess {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
