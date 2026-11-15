#![cfg(oneiron_test_support)]
//! L1-03 PR 4 (canon ARCH-0028 `#mcp-tasks` "Result mapping"; owner ruling
//! ONEIRON-MCP-TASKS = AB): an MCP task over the two other records the engine
//! keeps, and a task's end is final.
//!
//! - A Timer `host.wake` whose own request declares the Tasks extension
//!   answers a task over its night step's root, read through
//!   `vault.sieve.settlements.get` as the poller. It works while the step's
//!   outcome runs, and ends `completed` once the outcome no longer runs: a
//!   partial outcome ends `completed` and names itself, because settled is
//!   not success (ARCH-0026: poll "until the outcome is no longer running").
//!   Any other wake answers as before.
//! - An `ai.video` call so declared answers a task over its job's ticket,
//!   read through `ai.video.poll` as the poller (against a plain-HTTP fake
//!   provider). `tasks/cancel` reaches the provider through
//!   `ai.video.cancel`, which stops and drops the job, so the task ends
//!   `cancelled` at once and stays so.
//! - A task that ended refuses a cancel (the spec: a task in a terminal
//!   status is never cancelled), so a cancel never undoes finished work, and
//!   its end stays.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_tasks_records`.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, Uri};
use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::{AgentDispatcher, WorkflowProgress};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptResultRef, AttemptState,
    InterveneAttempt,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const TOOL_FIRST: &str = "/mcp/tool-first";
const TASKS: &str = "io.modelcontextprotocol/tasks";
const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The provider's id for the one video job the fake renders.
const PROVIDER_JOB: &str = "video_task_1";

/// A rooted vault behind the MCP gateway, called by its owner, with the
/// owner's saved two-step workflow.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    workflow: EntityId,
    /// The model host, when the server serves a provider: its workers stop
    /// when it drops.
    _host: Option<AiHost>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// The fixture with no model host: no worker runs any job.
    fn new() -> TestResult<Self> {
        let rooted = RootedVault::new()?;
        let app = build_app(Arc::new(sync_server(&rooted.vault)?));
        Ok(rooted.behind(app, None))
    }

    /// The fixture whose server serves one video seat on the plain-HTTP
    /// fake provider at `base_url`, keyed from the environment, with the
    /// Dreamer and the workflow pump off.
    async fn with_video_provider(base_url: &str) -> TestResult<Self> {
        let rooted = RootedVault::new()?;
        let models = ModelsConfig::from_toml(
            &format!(
                "[dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
                 [providers.paid]\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\n\
                 key_env = \"HOME\"\nrevision = \"v1\"\nlocality = \"own_server\"\n\
                 [media.video]\nrungs = [\"paid:video-small\"]\n"
            ),
            None,
        )?;
        let (server, host) = AiHost::attach(sync_server(&rooted.vault)?, Some(&models)).await;
        Ok(rooted.behind(build_app(Arc::new(server)), Some(host)))
    }
}

/// A rooted vault: its machines, its owner and the owner's root slip, and
/// the owner's saved two-step workflow.
struct RootedVault {
    dir: tempfile::TempDir,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    workflow: EntityId,
}

impl RootedVault {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let first = saved_agent(&vault, "records.first")?;
        let second = saved_agent(&vault, "records.second")?;
        let workflow = EntityId::now();
        vault.save_workflow(
            &workflow,
            &WorkflowDefinition::new("mcp task records", vec![first, second])?,
            2,
        )?;
        Ok(Self {
            dir,
            vault,
            issuer,
            root,
            workflow,
        })
    }

    /// The fixture of this vault behind `app`, served with `host`.
    fn behind(self, app: Router, host: Option<AiHost>) -> Fixture {
        Fixture {
            app,
            vault: self.vault,
            issuer: self.issuer,
            root: self.root,
            workflow: self.workflow,
            _host: host,
            _dir: self.dir,
        }
    }
}

fn sync_server(vault: &Arc<Vault>) -> TestResult<SyncServer> {
    SyncServer::new(
        Arc::clone(vault),
        SyncServerConfig {
            auth_secret: Some("mcp-tasks-records".into()),
            ..Default::default()
        },
    )
    .map_err(Into::into)
}

/// A plain-HTTP fake video provider: it queues one job, answers every poll
/// that the job renders at 10%, and stops it on a delete. It keeps every
/// request it saw, in order.
struct FakeVideoProvider {
    base_url: String,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeVideoProvider {
    async fn start() -> TestResult<Self> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let app = Router::new().fallback(move |method: Method, uri: Uri| {
            let log = Arc::clone(&log);
            async move {
                let path = uri.path().to_owned();
                if let Ok(mut seen) = log.lock() {
                    seen.push((method.as_str().to_owned(), path.clone()));
                }
                let job = format!("/v1/videos/{PROVIDER_JOB}");
                match (method.as_str(), path.as_str()) {
                    ("POST", "/v1/videos") => (
                        StatusCode::OK,
                        axum::Json(json!({ "id": PROVIDER_JOB, "status": "queued" })),
                    ),
                    ("GET", polled) if polled == job => (
                        StatusCode::OK,
                        axum::Json(
                            json!({ "id": PROVIDER_JOB, "status": "in_progress", "progress": 10 }),
                        ),
                    ),
                    ("DELETE", stopped) if stopped == job => (
                        StatusCode::OK,
                        axum::Json(json!({ "id": PROVIDER_JOB, "deleted": true })),
                    ),
                    _ => (
                        StatusCode::NOT_FOUND,
                        axum::Json(json!({ "error": { "message": "no such route" } })),
                    ),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base_url = format!("http://{}", listener.local_addr()?);
        tokio::spawn(async move {
            let _served = axum::serve(listener, app).await;
        });
        Ok(Self { base_url, seen })
    }

    /// Every request the provider saw, as (method, path), in order.
    fn seen(&self) -> Vec<(String, String)> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }
}

impl Fixture {
    /// One JSON-RPC request to the tool-first endpoint as the owner, under
    /// the root slip and a fresh holder proof: the parsed reply.
    async fn rpc(&self, method: &str, params: Value) -> TestResult<Value> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self.issuer.binding_proof(&self.root, &challenge)?;
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(TOOL_FIRST)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
            .header("authorization", format!("Bearer {}", self.root.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8_lossy(&bytes);
        let reply =
            serde_json::from_str(&body).unwrap_or_else(|_| Value::String(body.into_owned()));
        assert_eq!(status, 200, "{reply}");
        Ok(reply)
    }

    /// The owner's `tools/call` of the generated verb `name` over `input`,
    /// declaring the Tasks extension on this request when `declared`.
    async fn call(&self, name: &str, input: Value, declared: bool) -> TestResult<Value> {
        let mut params = json!({ "name": name, "arguments": verb_arguments(input) });
        if declared {
            params["_meta"] = declaration();
        }
        self.rpc("tools/call", params).await
    }

    /// A declared `tasks/<method>` on `task_id`.
    async fn tasks(&self, method: &str, task_id: &str) -> TestResult<Value> {
        self.rpc(
            &format!("tasks/{method}"),
            json!({ "taskId": task_id, "_meta": declaration() }),
        )
        .await
    }

    /// Runs the run's active step as a host does.
    fn run_step(&self, root: AttemptId, result: &str) -> TestResult<WorkflowProgress> {
        Ok(AgentDispatcher::new(&self.vault).run_workflow_step(
            root,
            "test-host",
            self.vault.now_recorded_at(),
            |_status, _context| AttemptResultRef::new(result),
        )?)
    }
}

/// A custom agent definition the pump can dispatch.
fn saved_agent(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.{name}");
    definition.instructions = Some("Write one note.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// A generated verb's tool-first arguments over its typed `input`.
fn verb_arguments(input: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "consent": {
            "policy_ref": "policy:agent-session",
            "purpose": "run the owner's night step and saved workflow",
        },
        "arguments": { "spec": input },
    })
}

/// A request's `_meta` declaring the Tasks extension.
fn declaration() -> Value {
    json!({ CLIENT_CAPABILITIES: { "extensions": { TASKS: {} } } })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A tool result's typed output.
fn output(result: &Value) -> &Value {
    &result["structuredContent"]["output"]["value"]
}

/// A declared start's task id.
fn task_id(reply: &Value) -> TestResult<String> {
    assert_eq!(
        reply["result"]["resultType"], "task",
        "a declared start answers a task: {reply}"
    );
    let id = reply["result"]["taskId"]
        .as_str()
        .ok_or_else(|| format!("a task names its id: {reply}"))?;
    assert_eq!(id.len(), 64, "{reply}");
    Ok(id.to_owned())
}

/// Runs `test` as the server's binary runs its app, on the engine's stack.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn a_timer_wake_returns_a_night_step_task_that_ends_with_its_outcome() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let started = fixture
            .call(
                "host.wake",
                json!({ "wake_kind": "timer", "queue_head": [] }),
                true,
            )
            .await?;
        let id = task_id(&started)?;
        assert_eq!(started["result"]["status"], "working", "{started}");

        let working = fixture.tasks("get", &id).await?;
        assert_eq!(working["result"]["status"], "working", "{working}");
        assert!(
            working["result"]["statusMessage"]
                .as_str()
                .is_some_and(|line| line.starts_with("waiting on ")),
            "the line counts what the step waits on: {working}"
        );
        assert!(
            working["result"].get("result").is_none(),
            "a working task carries no result: {working}"
        );

        // Every job the step queued (the vault holds no other work) stops
        // before it runs, so the step ends partial. No host runs here.
        let queue = AttemptQueue::new(&fixture.vault);
        let jobs: Vec<AttemptId> = queue
            .list()?
            .into_iter()
            .filter(|record| !record.state.is_terminal())
            .map(|record| record.id)
            .collect();
        assert!(!jobs.is_empty(), "the night step queued its jobs");
        for job in jobs {
            let state = queue.get(job)?.ok_or("the job is stored")?.state;
            if state.is_terminal() {
                continue;
            }
            queue.intervene(InterveneAttempt {
                id: job,
                kind: AttemptInterventionKind::Cancel,
                actor: "test-operator".to_owned(),
                note: None,
                now: fixture.vault.now_recorded_at(),
            })?;
        }

        let ended = fixture.tasks("get", &id).await?;
        assert_eq!(
            ended["result"]["status"], "completed",
            "a partial outcome ends the task completed: {ended}"
        );
        assert_eq!(
            ended["result"]["statusMessage"], "outcome partial",
            "{ended}"
        );
        let settlement = output(&ended["result"]["result"]);
        assert_eq!(
            settlement["outcome"]["state"], "partial",
            "the result names the outcome: {ended}"
        );
        assert_eq!(
            ended["result"]["result"]["isError"], false,
            "a partial outcome is no error: {ended}"
        );

        let refused = fixture.tasks("cancel", &id).await?;
        assert_eq!(
            refused["error"]["code"], -32602,
            "an ended task refuses a cancel: {refused}"
        );
        let again = fixture.tasks("get", &id).await?;
        assert_eq!(again["result"]["status"], "completed", "{again}");

        let other = fixture
            .call(
                "host.wake",
                json!({ "wake_kind": "event", "queue_head": [] }),
                true,
            )
            .await?;
        assert!(
            other["result"].get("taskId").is_none(),
            "a wake other than Timer starts no record a task wraps: {other}"
        );
        assert_eq!(
            output(&other["result"])["wake_kind"],
            "event",
            "it answers as before: {other}"
        );
        Ok(())
    })
}

#[test]
fn a_task_that_ended_refuses_a_cancel_and_keeps_its_end() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let started = fixture
            .call(
                "vault.workflows.dispatch",
                json!({
                    "workflow_ref": fixture.workflow.to_hex(),
                    "intent_key": "ended",
                    "briefing": "Write the two notes.",
                }),
                true,
            )
            .await?;
        let id = task_id(&started)?;
        let roots = AgentDispatcher::new(&fixture.vault).open_workflow_roots()?;
        let [root] = roots[..] else {
            return Err(format!("expected one open run, found {}", roots.len()).into());
        };
        assert!(matches!(
            fixture.run_step(root, "note:first")?,
            WorkflowProgress::Advanced(_)
        ));
        assert_eq!(
            fixture.run_step(root, "note:second")?,
            WorkflowProgress::Completed
        );

        let ended = fixture.tasks("get", &id).await?;
        assert_eq!(ended["result"]["status"], "completed", "{ended}");
        let created = ended["result"]["createdAt"].clone();

        let refused = fixture.tasks("cancel", &id).await?;
        assert_eq!(
            refused["error"]["code"], -32602,
            "a completed task refuses a cancel: {refused}"
        );
        assert!(
            refused["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("already completed")),
            "the refusal names the end, not a missing task: {refused}"
        );
        let after = fixture.tasks("get", &id).await?;
        assert_eq!(after["result"]["status"], "completed", "{after}");
        assert_eq!(after["result"]["createdAt"], created, "{after}");
        assert_eq!(
            AttemptQueue::new(&fixture.vault)
                .get(root)?
                .ok_or("the run's root is stored")?
                .state,
            AttemptState::Completed,
            "the refused cancel left the finished run as it was"
        );
        Ok(())
    })
}

#[test]
fn a_video_job_returns_a_task_and_its_cancel_reaches_the_provider() -> TestResult {
    on_engine_stack(|| async {
        let provider = FakeVideoProvider::start().await?;
        let fixture = Fixture::with_video_provider(&provider.base_url).await?;
        let started = fixture
            .call(
                "ai.video",
                json!({
                    "prompt": "A harbour at dawn",
                    "params": { "seconds": 4, "size": "1280x720" },
                }),
                true,
            )
            .await?;
        let id = task_id(&started)?;
        assert_eq!(started["result"]["status"], "working", "{started}");

        let rendering = fixture.tasks("get", &id).await?;
        assert_eq!(rendering["result"]["status"], "working", "{rendering}");
        assert_eq!(
            rendering["result"]["statusMessage"], "rendering, 10%",
            "the poll read the job at its provider: {rendering}"
        );

        let cancelled = fixture.tasks("cancel", &id).await?;
        assert_eq!(cancelled["result"]["resultType"], "complete", "{cancelled}");
        let stop = ("DELETE".to_owned(), format!("/v1/videos/{PROVIDER_JOB}"));
        assert!(
            provider.seen().contains(&stop),
            "the cancel reached the provider: {:?}",
            provider.seen()
        );

        let got = fixture.tasks("get", &id).await?;
        assert_eq!(
            got["result"]["status"], "cancelled",
            "the job stopped and was dropped, so the task ended cancelled: {got}"
        );
        assert!(
            got["result"].get("result").is_none(),
            "a cancelled task carries no result: {got}"
        );

        let again = fixture.tasks("cancel", &id).await?;
        assert_eq!(
            again["error"]["code"], -32602,
            "a cancelled task refuses another cancel: {again}"
        );
        assert_eq!(
            provider.seen().iter().filter(|seen| **seen == stop).count(),
            1,
            "the second cancel reached no provider"
        );
        Ok(())
    })
}
